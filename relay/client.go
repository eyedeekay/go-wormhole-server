package relay

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/chris-pikul/go-wormhole-server/config"
	"github.com/chris-pikul/go-wormhole-server/log"
	"github.com/chris-pikul/go-wormhole/errs"
	"github.com/chris-pikul/go-wormhole/msg"
	"github.com/gorilla/websocket"
)

const (
	readWait  = 60 * time.Second
	writeWait = 10 * time.Second

	pingInterval = (readWait * 9) / 10

	maxMessageSize = 1024
)

//Client wraps up the websocket connection
//with a sending buffer and functions for transfering messages
type Client struct {
	conn       *websocket.Conn
	sendBuffer chan msg.IMessage

	App       *Application
	Side      string
	Nameplate string

	Allocated bool
	Claimed bool
	Released bool
}

//IsBound returns true if the client has already bound to the server
func (c Client) IsBound() bool {
	return c.App != nil && c.Side != ""
}

func (c *Client) watchReads() {
	defer func() {
		unregister <- c
		c.conn.Close() //Close the actual connection here
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(readWait))

	//Setup the ping/pong response outside of message processing
	//which basically just extends the connection life
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(readWait))
		LogDebug(c, "received pong from client")
		return nil
	})

	//Start accepting messages and processing them
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil { // Read/Connection error
			if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				LogErr(c, "reading from socket connection", err)
			}
			break //Leave the loop, so unregister
		}

		LogDebugf(c, "received message from client %s", string(message))

		//Process the message
		c.OnMessage(message)
	}
}

func (c *Client) watchWrites() {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close() //Double check the connection is closed
	}()

	for {
		select {
		case msgObj, ok := <-c.sendBuffer: //Read messages to send
			//Give them 10 seconds to take the new message
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))

			if !ok {
				//Channel was closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				log.Debug("write channel was closed, disconnecting client")
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil { //Failed to get a write channel
				log.Debug("failed to get a writer for client")
				return
			}
			if err = json.NewEncoder(w).Encode(msgObj); err != nil {
				LogErr(c, "failed to encode message", err)
			}

			if err := w.Close(); err != nil { //Writer failure
				return
			}
		case <-ticker.C: //Ping check for keeping the connection alive
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Debug("failed to write ping, disconnecting client")
				return //Failed to write ping
			}
			LogDebug(c, "sent ping message to client")
		}
	}
}

//OnConnect is called when the client has successfully been registered
//to the server
func (c *Client) OnConnect() {
	c.sendBuffer <- msg.Welcome{
		Message: msg.NewServerMessage(msg.TypeWelcome),

		Info: service.Welcome,
	}
}

//OnMessage called when a message from the client is received
//and it needs to be handled/processed.
//From this point we have a message as only the bytes and
//need to handle it appropriately. We need to do all steps
//and validation here as necessary. So this will be broken
//down into the message types.
func (c *Client) OnMessage(src []byte) {
	mt, im, err := msg.ParseClient(src)
	if err != nil {
		c.messageError(err, src)
		return
	}

	LogInfof(c, "received message %s", mt.String())

	//TODO: Find the ID thing
	c.sendBuffer <- msg.Ack{
		Message: msg.NewServerMessage(msg.TypeAck),
		ID:      0, //Not sure where this comes from yet
	}

	//Quit ahead if we haven't bound and aren't going to
	if c.IsBound() == false && mt != msg.TypePing && mt != msg.TypeBind {
		c.messageError(errs.ErrBindFirst, src)
		return
	} else if c.IsBound() && (c.App == nil || c.Side == "") {
		//Something went wrong in the memory
		LogError(c, "client does not have a bound App, but should")
		c.messageError(errs.ErrInternal, src)
	}

	var e error
	switch mt {
	case msg.TypePing:
		m := im.(msg.Ping)
		c.HandlePing(m)
	case msg.TypeBind:
		m := im.(msg.Bind)
		e = c.HandleBind(m)
	case msg.TypeList:
		m := im.(msg.List)
		e = c.HandleList(m)
	case msg.TypeAllocate:
		m := im.(msg.Allocate)
		e = c.HandleAllocate(m)
	case msg.TypeClaim:
		m := im.(msg.Claim)
		e = c.HandleClaim(m)
	case msg.TypeRelease:
		m := im.(msg.Release)
		e = c.HandleRelease(m)
	default:
		c.messageError(fmt.Errorf("unsuported command '%s'", mt.String()), src)
	}

	if e != nil {
		c.messageError(e, src)
	}
}

//when bad or malformed messages appear, this method
//will create the necessary error response and send it to
//the client. These are generally only validation/protocol
//errors and not actual networking errors
func (c *Client) messageError(err error, orig []byte) {
	LogErr(c, "error from client message", err)

	if err == msg.ErrUnknown {
		//Convert to the reply type
		err = errs.ErrUnknownType
	}

	//Mask the error if it isn't a client one
	if _, ok := err.(errs.ClientError); !ok {
		LogErr(c, "internal error found during messageError before going to client", err)
		err = errs.ErrInternal
	}
	
	c.sendBuffer <- msg.Error{
		Message: msg.NewServerMessage(msg.TypeError),
		Error:   err.Error(),
		Orig:    orig,
	}
}

//HandlePing handles ping messages and responds back
//with the matching Pong message
func (c *Client) HandlePing(m msg.Ping) {
	c.sendBuffer <- msg.Pong{
		Message: msg.NewServerMessage(msg.TypePong),
		Pong:    m.Ping,
	}
	LogDebugf(c, "received ping %d", m.Ping)
}

//HandleBind handles bind messages.
func (c *Client) HandleBind(m msg.Bind) error {
	if c.IsBound() {
		return errs.ErrBound //Already bound
	} else if m.AppID == "" {
		return errs.ErrBindAppID
	} else if m.Side == "" {
		return errs.ErrBindSide
	}

	c.App = service.GetApp(m.AppID)
	c.Side = m.Side

	LogInfof(c, "bound client to app %s and side %s", m.AppID, m.Side)
	return nil
}

//HandleList handles list commands from the client
//who would like to know the available nameplates.
//This is optional for whether the server will allow
//it via the AllowList relay server configuration option.
//If this option is not available, an empty list is returned
//back to the client
func (c *Client) HandleList(m msg.List) error {
	//Safe to assume we are bound

	if config.Opts.Relay.AllowList == false {
		//Not allowed, reply empty
		c.sendBuffer <- msg.Nameplates{
			Message:    msg.NewServerMessage(msg.TypeNameplates),
			Nameplates: []msg.NameplateEntry{},
		}
		return nil
	}

	//Get the nameplates since we allow it
	ids, err := c.App.GetNameplateIDs()
	if err != nil {
		LogErr(c, "failed to get nameplate IDs for List command", err)
		return errs.ErrInternal
	}

	resp := msg.Nameplates{
		Message:    msg.NewServerMessage(msg.TypeNameplates),
		Nameplates: make([]msg.NameplateEntry, 0),
	}
	for _, id := range ids {
		resp.Nameplates = append(resp.Nameplates, msg.NameplateEntry{ID: id})
	}

	c.sendBuffer <- resp

	return nil
}

//HandleAllocate command is received from client when
//they want to allocate, or reserve, a nameplate slot
//for message transfer.
//Clients can only allocate 1 during a connection.
//Allocate generates a new nameplate and returns it
func (c *Client) HandleAllocate(m msg.Allocate) error {
	if c.Allocated {
		//Already allocated, reply with error
		return errs.ErrAlreadyAllocated
	}

	id, err := c.App.AllocateNameplate(c.Side)
	if err != nil {
		LogErr(c, "failed to allocate nameplate for allocate command", err)
		return err
	}

	c.Allocated = true

	c.sendBuffer <- msg.Allocated{
		Message:   msg.NewServerMessage(msg.TypeAllocated),
		Nameplate: id,
	}
	return nil
}

//HandleClaim command from client when they want
//to claim a specific nameplate instead of
//auto-generating one for them.
//Clients can only allocate 1 during a connection.
func (c *Client) HandleClaim(m msg.Claim) error {
	if c.Claimed {
		return errs.ErrAlreadyClaimed
	}

	if m.Nameplate == "" {
		return errs.ErrClaimNameplate
	}

	mboxID, err := c.App.ClaimNameplate(m.Nameplate, m.Nameplate)
	if err != nil {
		LogErr(c, "failed to claim nameplate for claim command", err)
		return err
	}

	c.Claimed = true
	c.Nameplate = m.Nameplate

	c.sendBuffer <- msg.Claimed{
		Message: msg.NewServerMessage(msg.TypeClaimed),
		Mailbox: mboxID,
	}

	return nil
}

//HandleRelease command from client when they want
//to release their hold, or side, of a nameplate.
//They can provide the nameplate as a means of double checking
//but the current client one is inferred.
//If they do supply it, it must match.
//This command must come after claim.
func (c *Client) HandleRelease(m msg.Release) error {
	if c.Released {
		return errs.ErrAlreadyReleased
	}

	//Check if they supplied it and it is different
	if m.Nameplate != "" && m.Nameplate != c.Nameplate {
		return errs.ErrReleaseNameplate
	} else if m.Nameplate == "" && c.Nameplate == "" {
		return errs.ErrReleaseNotClaimed
	}

	err := c.App.ReleaseNameplate(c.Nameplate, c.Side)
	if err != nil {
		LogErr(c, "failed to release nameplate for release command", err)
		return err
	}

	c.Released = true

	c.sendBuffer <- msg.Released{
		Message: msg.NewServerMessage(msg.TypeReleased),
	}

	return nil
}