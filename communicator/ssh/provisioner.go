package ssh

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/hashicorp/terraform/terraform"
	"github.com/mitchellh/go-homedir"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// DefaultUser is used if there is no user given
	DefaultUser = "root"

	// DefaultPort is used if there is no port given
	DefaultPort = 22

	// DefaultScriptPath is used as the path to copy the file to
	// for remote execution if not provided otherwise.
	DefaultScriptPath = "/tmp/terraform_%RAND%.sh"

	// DefaultTimeout is used if there is no timeout given
	DefaultTimeout = 5 * time.Minute
)

// connectionInfo is decoded from the ConnInfo of the resource. These are the
// only keys we look at. If a KeyFile is given, that is used instead
// of a password.
type connectionInfo struct {
	User       string
	Password   string
	KeyFile    string `mapstructure:"key_file"`
	Host       string
	Port       int
	Agent      bool
	Timeout    string
	ScriptPath string        `mapstructure:"script_path"`
	TimeoutVal time.Duration `mapstructure:"-"`

	BastionUser     string `mapstructure:"bastion_user"`
	BastionPassword string `mapstructure:"bastion_password"`
	BastionKeyFile  string `mapstructure:"bastion_key_file"`
	BastionHost     string `mapstructure:"bastion_host"`
	BastionPort     int    `mapstructure:"bastion_port"`
}

// parseConnectionInfo is used to convert the ConnInfo of the InstanceState into
// a ConnectionInfo struct
func parseConnectionInfo(s *terraform.InstanceState) (*connectionInfo, error) {
	connInfo := &connectionInfo{}
	decConf := &mapstructure.DecoderConfig{
		WeaklyTypedInput: true,
		Result:           connInfo,
	}
	dec, err := mapstructure.NewDecoder(decConf)
	if err != nil {
		return nil, err
	}
	if err := dec.Decode(s.Ephemeral.ConnInfo); err != nil {
		return nil, err
	}

	if connInfo.User == "" {
		connInfo.User = DefaultUser
	}
	if connInfo.Port == 0 {
		connInfo.Port = DefaultPort
	}
	if connInfo.ScriptPath == "" {
		connInfo.ScriptPath = DefaultScriptPath
	}
	if connInfo.Timeout != "" {
		connInfo.TimeoutVal = safeDuration(connInfo.Timeout, DefaultTimeout)
	} else {
		connInfo.TimeoutVal = DefaultTimeout
	}

	// Default all bastion config attrs to their non-bastion counterparts
	if connInfo.BastionHost != "" {
		if connInfo.BastionUser == "" {
			connInfo.BastionUser = connInfo.User
		}
		if connInfo.BastionPassword == "" {
			connInfo.BastionPassword = connInfo.Password
		}
		if connInfo.BastionKeyFile == "" {
			connInfo.BastionKeyFile = connInfo.KeyFile
		}
		if connInfo.BastionPort == 0 {
			connInfo.BastionPort = connInfo.Port
		}
	}

	return connInfo, nil
}

// safeDuration returns either the parsed duration or a default value
func safeDuration(dur string, defaultDur time.Duration) time.Duration {
	d, err := time.ParseDuration(dur)
	if err != nil {
		log.Printf("Invalid duration '%s', using default of %s", dur, defaultDur)
		return defaultDur
	}
	return d
}

// prepareSSHConfig is used to turn the *ConnectionInfo provided into a
// usable *SSHConfig for client initialization.
func prepareSSHConfig(connInfo *connectionInfo) (*sshConfig, error) {
	var conn net.Conn
	var err error
	var sshAgent agent.Agent

	sshConf := &ssh.ClientConfig{
		User: connInfo.User,
	}
	var bastionConf *ssh.ClientConfig
	if connInfo.BastionHost != "" {
		bastionConf = &ssh.ClientConfig{
			User: connInfo.User,
		}
	}
	if connInfo.Agent {
		sshAuthSock := os.Getenv("SSH_AUTH_SOCK")

		if sshAuthSock == "" {
			return nil, fmt.Errorf("SSH Requested but SSH_AUTH_SOCK not-specified")
		}

		conn, err = net.Dial("unix", sshAuthSock)
		if err != nil {
			return nil, fmt.Errorf("Error connecting to SSH_AUTH_SOCK: %v", err)
		}
		// I need to close this but, later after all connections have been made
		// defer conn.Close()
		sshAgent = agent.NewClient(conn)
		agentAuth := ssh.PublicKeysCallback(sshAgent.Signers)
		sshConf.Auth = append(sshConf.Auth, agentAuth)
		if bastionConf != nil {
			bastionConf.Auth = append(bastionConf.Auth, agentAuth)
		}
	}
	if connInfo.KeyFile != "" {
		signer, err := readPublicKeyFromPath(connInfo.KeyFile)
		if err != nil {
			return nil, err
		}
		sshConf.Auth = append(sshConf.Auth, ssh.PublicKeys(signer))
	}
	if bastionConf != nil && connInfo.BastionKeyFile != "" {
		signer, err := readPublicKeyFromPath(connInfo.BastionKeyFile)
		if err != nil {
			return nil, err
		}
		bastionConf.Auth = append(bastionConf.Auth, ssh.PublicKeys(signer))
	}
	sshConf.Auth = append(sshConf.Auth,
		authMethodsFromPassword(connInfo.Password)...)
	if bastionConf != nil {
		bastionConf.Auth = append(bastionConf.Auth,
			authMethodsFromPassword(connInfo.BastionPassword)...)
	}
	host := fmt.Sprintf("%s:%d", connInfo.Host, connInfo.Port)

	connectFunc := ConnectFunc("tcp", host)

	if bastionConf != nil {
		bastionHost := fmt.Sprintf("%s:%d", connInfo.BastionHost, connInfo.BastionPort)
		connectFunc = BastionConnectFunc(
			"tcp", bastionHost, bastionConf, "tcp", host)
	}

	config := &sshConfig{
		config:       sshConf,
		connection:   connectFunc,
		sshAgentConn: conn,
		sshAgent:     sshAgent,
	}
	return config, nil
}

func readPublicKeyFromPath(path string) (ssh.Signer, error) {
	fullPath, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to expand home directory: %v", err)
	}
	key, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read key file '%s': %v", path, err)
	}

	// We parse the private key on our own first so that we can
	// show a nicer error if the private key has a password.
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf(
			"Failed to read key '%s': no key found", path)
	}
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return nil, fmt.Errorf(
			"Failed to read key '%s': password protected keys are\n"+
				"not supported. Please decrypt the key prior to use.", path)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse key file '%s': %v", path, err)
	}

	return signer, nil
}

func authMethodsFromPassword(pw string) []ssh.AuthMethod {
	var methods []ssh.AuthMethod
	if pw != "" {
		methods = append(methods, ssh.Password(pw))
		methods = append(methods,
			ssh.KeyboardInteractive(PasswordKeyboardInteractive(pw)))
	}

	return methods
}
