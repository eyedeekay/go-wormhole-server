package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"

	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/chris-pikul/go-wormhole-server/log"
	"github.com/urfave/cli"
)

//RelayOptions holds the settings specific to the relay
//server operations
type RelayOptions struct {
	//Host portion for the servers to listen on.
	//Leaving this empty is fine as it will just use the default interface.
	Host string `json:"host"`

	//Port number for the server to listen on
	Port uint `json:"port"`

	//I2P SAM address for running a hidden service
	I2P string `json:i2p`

	//WelcomeMOTD set's the welcome message to be displayed on connecting
	//clients
	WelcomeMOTD string `json:"welcomeMOTD"`

	//WelcomeError is displayed to clients, and if provided will have
	//them disconnect immediately
	WelcomeError string `json:"welcomeError"`

	//DBFile path to the SQLite database file for the server to use
	DBFile string `json:"dbFile"`

	//AllowList allows clients to request a list of available nameplates
	AllowList bool `json:"allowList"`

	//CurrentVersion holds the current wormhole client version
	CurrentVersion string `json:"currentVersion"`

	//AdvertisedVersion holds the newest release version, which
	//will be advertised to clients to alert them of a new update
	AdvertisedVersion string `json:"advertisedVersion"`

	//CleaningInterval holds the time interval in which cleaning
	//operations should be ran
	CleaningInterval uint `json:"cleaningInterval"`

	//ChannelExpiration holds the time duration in which a channel
	//can exist without interaction before it is marked as dirty
	//and removed by cleaning. It is recommended this be larger
	//than the CleaningInterval field
	ChannelExpiration uint `json:"channelExpiration"` //TODO: This value is never used
}

//TransitOptions holds the settings specific to the transit
//(piping) server
type TransitOptions struct {
	//Host portion for the servers to listen on.
	//Leaving this empty is fine as it will just use the default interface.
	Host string `json:"host"`

	//Port number for the server to listen on
	Port uint `json:"port"`

	//I2P SAM address for running a hidden service
	I2P string `json:i2p`
}

const (
	//ModeBoth specifies to run both relay, and transit
	ModeBoth = "BOTH"

	//ModeRelay specifies to run only the relay portion
	ModeRelay = "RELAY"

	//ModeTransit specifies to run only the transit portion
	ModeTransit = "TRANSIT"
)

//Options is a JSON serializable object holding the configuration
//settings for running a Wormhole Server.
//
//These options can be loaded from file, or filled in from command line.
//The intended hierarchy is CLI options > File > Defaults
type Options struct {
	//Mode specifies in which mode should the server operate.
	//Options are:
	// - BOTH (default): Runs both the relay and transit servers on the
	//		same instance
	// - RELAY: Only run the relay server
	// - TRANSIT: Only run the transit server
	Mode string `json:"mode"`

	//Relay holds the relay portion options
	Relay RelayOptions `json:"relay"`

	//Transit holds the transit portion options
	Transit TransitOptions `json:"transit"`

	//Logging holds the options settings for logging operations
	Logging log.Options `json:"logging"`
}

//DefaultOptions contains the preset default options
//for a server.
var DefaultOptions = Options{
	Mode: ModeBoth,

	Relay: RelayOptions{
		Host:              "",
		Port:              4000,
		DBFile:            "./wormhole-relay.db",
		I2P:               "",
		AllowList:         true,
		CleaningInterval:  5,
		ChannelExpiration: 11,
	},

	Transit: TransitOptions{
		Host: "",
		Port: 4001,
	},

	Logging: log.DefaultOptions,
}

var (
	//ErrOptionsMode validation error for mode
	ErrOptionsMode = errors.New("server mode invalid")

	//ErrOptionsCleaning validation error that cleaning interval
	//is larger then the channel expiration
	ErrOptionsCleaning = errors.New("cleaning interval should be less then channel expiration")
)

//Equals returns true if the supplied options matches these ones (this).
//Performs this as a deep-equals operation
func (o Options) Equals(opts Options) bool {
	return o.Mode == opts.Mode &&
		o.Relay == opts.Relay &&
		o.Transit == opts.Transit &&
		o.Logging.Equals(opts.Logging)
}

//Verify checks the Options fields for validity.
//Returns an error if a problem is incountered
func (o Options) Verify() error {
	if o.Mode != ModeBoth &&
		o.Mode != ModeRelay &&
		o.Mode != ModeTransit {
		return ErrOptionsMode
	}

	if o.Relay.CleaningInterval > o.Relay.ChannelExpiration {
		return ErrOptionsCleaning
	}

	return o.Logging.Verify()
}

//MergeFrom combines the fields from the supplied Options parameter
//into this object (smartly where applicable) and run Verify on itself,
//returning the validation error if any happened.
func (o *Options) MergeFrom(opt Options) error {
	o.Mode = opt.Mode

	o.Relay = opt.Relay
	o.Transit = opt.Transit

	err := o.Logging.MergeFrom(opt.Logging)
	if err != nil {
		return err
	}
	return o.Verify()
}

//ReadOptionsFromFile opens the provided JSON file and marshals the data
//into a Options object.
//Returns the results, and the first error encountered.
//The error is either validation error, or JSON encoding error.
func ReadOptionsFromFile(filename string) (Options, error) {
	res := DefaultOptions

	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return res, err
	}

	err = json.Unmarshal([]byte(file), &res)
	if err != nil {
		return res, err
	}

	return res, res.Verify()
}

//NewOptions compiles the Options object from the provided sources.
//Will use a custom defaults, or if nil the DefaultOptions object is used.
//Then will search the fileName json file (if provided) for options.
//Then will combine the CLI options provided from main().
//These options cascade in order where applicable for the option.
//Will run the Options.Verify() method and return the error after compilation
func NewOptions(defaults *Options, filename string, ctx *cli.Context) (Options, error) {
	res := DefaultOptions
	if defaults != nil {
		res = *defaults
	}

	if len(filename) > 0 {
		fmt.Printf("reading configuration from '%s'\n", filename)
		file, err := ReadOptionsFromFile(filename)
		if err != nil {
			return res, err
		}
		err = res.MergeFrom(file)
		if err != nil {
			return res, err
		}
	}

	if ctx != nil {
		fmt.Printf("applying CLI options to configuration\n")
		applyCLIOptions(ctx, &res)
	}

	return res, res.Verify()
}

//applyCLIOptions writes the options presented in the CLI arguments to
//the provided ServerOptions object, overriding anything there previously
func applyCLIOptions(c *cli.Context, opts *Options) {
	if c == nil || opts == nil { //Safe-gaurd
		return
	}

	if c.String("config") != "" {
		//config file was used, ignore the flags
		return
	}

	opts.Relay.Host = c.String("relay-host")
	opts.Relay.Port = c.Uint("relay-port")
	opts.Relay.I2P = c.String("i2p")
	opts.Transit.Host = c.String("transit-host")
	opts.Transit.Port = c.Uint("transit-port")
	opts.Transit.I2P = c.String("i2p")

	opts.Relay.DBFile = c.String("db")

	if c.Bool("no-list") {
		opts.Relay.AllowList = false
	}

	if c.String("advert-version") != "" {
		opts.Relay.AdvertisedVersion = c.String("advert-version")
	}

	if c.Uint("cleaning") > 0 {
		ci := c.Uint("cleaning")
		opts.Relay.CleaningInterval = ci
	}

	if c.Uint("channel-exp") > 0 {
		ce := c.Uint("channel-exp")
		opts.Relay.ChannelExpiration = ce
	}

	opts.Logging.Path = c.String("log")

	if str := c.String("log-level"); str != "" {
		opts.Logging.Level = str
	}

	opts.Logging.BlurTimes = c.Uint("log-blur")
}

func CreateTLSCertificate(host string) error {
	fmt.Println("Generating TLS keys. This may take a minute...")
	priv, err := ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
	if err != nil {
		return err
	}

	tlsCert, err := NewTLSCertificate(host, priv)
	if nil != err {
		return err
	}

	// save the TLS certificate
	certOut, err := os.Create(host + ".crt")
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", host+".crt", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})
	certOut.Close()
	fmt.Printf("\tTLS certificate saved to: %s\n", host+".crt")

	// save the TLS private key
	privFile := host + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", privFile, err)
	}
	secp384r1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}) // http://www.ietf.org/rfc/rfc5480.txt
	pem.Encode(keyOut, &pem.Block{Type: "EC PARAMETERS", Bytes: secp384r1})
	ecder, err := x509.MarshalECPrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecder})
	pem.Encode(keyOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})

	keyOut.Close()
	fmt.Printf("\tTLS private key saved to: %s\n", privFile)

	// CRL
	crlFile := host + ".crl"
	crlOut, err := os.OpenFile(crlFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", crlFile, err)
	}
	crlcert, err := x509.ParseCertificate(tlsCert)
	if err != nil {
		return fmt.Errorf("Certificate with unknown critical extension was not parsed: %s", err)
	}

	now := time.Now()
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   crlcert.SerialNumber,
			RevocationTime: now,
		},
	}

	crlBytes, err := crlcert.CreateCRL(crand.Reader, priv, revokedCerts, now, now)
	if err != nil {
		return fmt.Errorf("error creating CRL: %s", err)
	}
	_, err = x509.ParseDERCRL(crlBytes)
	if err != nil {
		return fmt.Errorf("error reparsing CRL: %s", err)
	}
	pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	crlOut.Close()
	fmt.Printf("\tTLS CRL saved to: %s\n", crlFile)

	return nil
}

func NewTLSCertificate(host string, priv *ecdsa.PrivateKey) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(5 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crand.Int(crand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         host,
		},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.ECDSAWithSHA512,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}
