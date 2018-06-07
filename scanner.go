package main

import (
	"regexp"
	"encoding/json"
	"io"
	"github.com/fatih/color"
)

var patterns []Pattern

type Pattern struct {
	Description string
	SecretType string
	Value string
	Regex *regexp.Regexp
}

func compileSecretPatterns(){
	var temp []Pattern
	if err := json.Unmarshal(patternsJson, &temp); err != nil {
		panic(err)
	}
	patterns = temp[:0]
	for _, i := range temp{
		i.Regex = regexp.MustCompile(i.Value)
		patterns = append(patterns, i)
	}
}

func scanFilename(filename string, loc string) {
	for _, i := range patterns{
		if i.SecretType == "Filename" &&i.Regex.MatchString(filename){
			color.Green("|Found match %s %s %s %s", filename, i.Description, i.Value, loc)
			break
		}
	}
}

func scanFileContent(reader io.Reader){
	/*
	for _, i := range patterns{
		if i.regex.MatchString(reader){
			color.Green("Found match %s", filename)
		}
	}
	*/
}

var patternsJson = []byte(`[
    {
        "description": "Azure storage standard key format", 
        "secretType": "FileContent", 
        "value": "\\b[A-Za-z0-9/+-]{86}\\b"
    }, 
    {
        "description": "Azure service bus standard key format", 
        "secretType": "FileContent", 
        "value": "\\b[A-Za-z0-9/+-]{43}\\b"
    }, 
    {
        "description": "Azure service configuration file", 
        "secretType": "Filename", 
        "value": "\\.cscfg$"
    }, 
    {
        "description": "Decryption Key", 
        "secretType": "FileContent", 
        "value": "CryptDeriveKey"
    }, 
    {
        "description": "Encryption Key", 
        "secretType": "FileContent", 
        "value": "CryptGenKey"
    }, 
    {
        "description": "Encryption Key", 
        "secretType": "FileContent", 
        "value": "HMACSHA1"
    }, 
    {
        "description": "Machine Key", 
        "secretType": "FileContent", 
        "value": "machinekey"
    }, 
    {
        "description": "Potential MSBuild publish profile", 
        "secretType": "Filename", 
        "value": "\\.pubxml(\\.user)?$"
    }, 
    {
        "description": "RDP file", 
        "secretType": "Filename", 
        "value": "\\.rdp$"
    }, 
    {
        "description": "Private client certificate", 
        "secretType": "Filename", 
        "value": "\\.pfx$"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": "\\.pkcs12$"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": "\\.p12$"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": "\\.asc$"
    }, 
    {
        "description": "Possible public key", 
        "secretType": "Filename", 
        "value": "\\.pub$"
    }, 
    {
        "description": "Potential Jenkins credentials file", 
        "secretType": "Filename", 
        "value": "^cred[\\s\\S]*xml"
    }, 
    {
        "description": "Database file", 
        "secretType": "Filename", 
        "value": "\\.mdf$"
    }, 
    {
        "description": "Database file", 
        "secretType": "Filename", 
        "value": "\\.sdf$"
    }, 
    {
        "description": "Database file", 
        "secretType": "Filename", 
        "value": "\\.sql$"
    }, 
    {
        "description": "Database file", 
        "secretType": "Filename", 
        "value": "\\.sqlite$"
    }, 
    {
        "description": "MySQL client command history file", 
        "secretType": "Filename", 
        "value": "^[\\s\\S]*mysql_history"
    }, 
    {
        "description": "PostgreSQL client command history file", 
        "secretType": "Filename", 
        "value": "^[\\s\\S]*psql_history"
    }, 
    {
        "description": "Ruby On Rails database configuration file", 
        "secretType": "Filename", 
        "value": "^database[\\s\\S]*.yml"
    }, 
    {
        "description": "AWS access key", 
        "secretType": "FileContent", 
        "value": "\\b[A-Za-z0-9/+-]{40}\\b"
    }, 
    {
        "description": "Network traffic capture file", 
        "secretType": "Filename", 
        "value": "\\.pcap$"
    }, 
    {
        "description": "Pidgin chat client account configuration file", 
        "secretType": "Filename", 
        "value": "accounts[\\s\\S]*.xml"
    }, 
    {
        "description": "Wordpress configuration file", 
        "secretType": "Filename", 
        "value": "wp-config[\\s\\S]*.php"
    }, 
    {
        "description": "Hexchat/XChat IRC client server list configuration file", 
        "secretType": "Filename", 
        "value": ".?xchat2[\\s\\S]*.conf"
    }, 
    {
        "description": "S3cmd configuration file", 
        "secretType": "Filename", 
        "value": "\\.s3cfg$"
    }, 
    {
        "description": "T command-line Twitter client configuration file", 
        "secretType": "Filename", 
        "value": "\\.trc$"
    }, 
    {
        "description": "OpenVPN client configuration file", 
        "secretType": "Filename", 
        "value": "\\.ovpn$"
    }, 
    {
        "description": "Ruby On Rails secret token configuration file", 
        "secretType": "Filename", 
        "value": "secret_token"
    }, 
    {
        "description": "OmniAuth configuration file", 
        "secretType": "Filename", 
        "value": "\\.omniauth$"
    }, 
    {
        "description": "Carrierwave configuration file", 
        "secretType": "Filename", 
        "value": "carrierwave"
    }, 
    {
        "description": "Client SSH Config", 
        "secretType": "Filename", 
        "value": ".?ssh_config[\\s\\S]*"
    }, 
    {
        "description": "Server SSH Config", 
        "secretType": "Filename", 
        "value": ".?sshd_config[\\s\\S]*"
    }, 
    {
        "description": "KeePass password manager database file", 
        "secretType": "Filename", 
        "value": "\\.kdb$"
    }, 
    {
        "description": "Contains word: backup", 
        "secretType": "Filename", 
        "value": "\\.backup$"
    }, 
    {
        "description": "Jenkins publish over SSH plugin file", 
        "secretType": "Filename", 
        "value": "jenkins.plugins.publish_over_ssh[^ ]*.xml"
    }, 
    {
        "description": "Potential MediaWiki configuration file", 
        "secretType": "Filename", 
        "value": "LocalSettings[^ ]*php"
    }, 
    {
        "description": "Rubygems credentials file", 
        "secretType": "Filename", 
        "value": "\\A\\.?gem/credentials\\z"
    }, 
    {
        "description": "SSH file", 
        "secretType": "Filename", 
        "value": "\\.ssh$"
    }, 
    {
        "description": "Github Dev API key", 
        "secretType": "FileContent", 
        "value": "jekyll_github_token[^ ]*"
    }, 
    {
        "description": "DHCP server configs", 
        "secretType": "Filename", 
        "value": "dhcpd[^ ]*.conf"
    }, 
    {
        "description": "Heroku Environment Variable", 
        "secretType": "FileContent", 
        "value": "heroku config:set"
    }, 
    {
        "description": "Jupyter Configuration file", 
        "secretType": "Filename", 
        "value": "jupyter[^ ]*config[^ ]*.json"
    }, 
    {
        "description": "bitlocker", 
        "secretType": "Filename", 
        "value": "\\.bek$"
    }, 
    {
        "description": "bitlocker", 
        "secretType": "Filename", 
        "value": "\\.tpm$"
    }, 
    {
        "description": "bitlocker", 
        "secretType": "Filename", 
        "value": "\\.fve$"
    },  
    {
        "description": "java key store", 
        "secretType": "Filename", 
        "value": "\\.jks$"
    }, 
    {
        "description": "openssl .key, apple .keychain, etc.", 
        "secretType": "Filename", 
        "value": "\\.key$"
    }, 
    {
        "description": "passwordsafe", 
        "secretType": "Filename", 
        "value": "\\.psafe3$"
    }, 
    {
        "description": "PKCS15 tokens", 
        "secretType": "Filename", 
        "value": "\\.p15$"
    }, 
    {
        "description": "mozilla", 
        "secretType": "Filename", 
        "value": "cert8.db"
    }, 
    {
        "description": "sql", 
        "secretType": "Filename", 
        "value": "connect.inc"
    }, 
    {
        "description": "dbman", 
        "secretType": "Filename", 
        "value": "default.pass"
    }, 
    {
        "description": "apache/nginx", 
        "secretType": "Filename", 
        "value": "htaccess"
    }, 
    {
        "description": "openssh", 
        "secretType": "Filename", 
        "value": "id_dsa"
    }, 
    {
        "description": "openssh", 
        "secretType": "Filename", 
        "value": "id_ecdsa"
    }, 
    {
        "description": "openssh", 
        "secretType": "Filename", 
        "value": "id_ed25519"
    }, 
    {
        "description": "openssh", 
        "secretType": "Filename", 
        "value": "id_rsa"
    }, 
    {
        "description": "mozilla", 
        "secretType": "Filename", 
        "value": "key3.db"
    }, 
    {
        "description": "typo3", 
        "secretType": "Filename", 
        "value": "localconf"
    }, 
    {
        "description": "wikimedia", 
        "secretType": "Filename", 
        "value": "localsettings"
    }, 
    {
        "description": "~/.netrc", 
        "secretType": "Filename", 
        "value": "\\.netrc$"
    }, 
    {
        "description": "libpurple otr fingerprints", 
        "secretType": "Filename", 
        "value": "otr.fingerprints"
    }, 
    {
        "description": "pgp", 
        "secretType": "Filename", 
        "value": "pgplog"
    }, 
    {
        "description": "pgp", 
        "secretType": "Filename", 
        "value": "pgppolicy.xml"
    }, 
    {
        "description": "pgp", 
        "secretType": "Filename", 
        "value": "pgpprefs.xml"
    }, 
    {
        "description": "gnupg", 
        "secretType": "Filename", 
        "value": "secring\\.gpg"
    }, 
    {
        "description": "sftp", 
        "secretType": "Filename", 
        "value": "sftp-config"
    }, 
    {
        "description": "freebsd", 
        "secretType": "Filename", 
        "value": "spwd.bd"
    }, 
    {
        "description": ".net", 
        "secretType": "Filename", 
        "value": "users.xml"
    }, 
    {
        "description": "bitcoin", 
        "secretType": "Filename", 
        "value": "wallet.dat"
    }, 
    {
        "description": "Private SSH key", 
        "secretType": "Filename", 
        "value": "\\A.*_rsa\\z"
    }, 
    {
        "description": "Private SSH key", 
        "secretType": "Filename", 
        "value": "\\A.*_dsa\\z"
    }, 
    {
        "description": "Private SSH key", 
        "secretType": "Filename", 
        "value": "\\A.*_ed25519\\z"
    }, 
    {
        "description": "Private SSH key", 
        "secretType": "Filename", 
        "value": "\\A.*_ecdsa\\z"
    }, 
    {
        "description": "SSH configuration file", 
        "secretType": "Filename", 
        "value": "\\.?ssh/config\\z"
    }, 
    {
        "description": "Potential cryptographic private key", 
        "secretType": "Filename", 
        "value": "\\Akey(pair)?\\z"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": ".pkcs12$"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": ".pfx$"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": ".p12$"
    }, 
    {
        "description": "Potential cryptographic key bundle", 
        "secretType": "Filename", 
        "value": ".asc$"
    }, 
    {
        "description": "Pidgin OTR private key", 
        "secretType": "Filename", 
        "value": ".otr.private_key"
    }, 
    {
        "description": "Shell command history file", 
        "secretType": "Filename", 
        "value": "\\A\\.?(bash_|zsh_|z)?history\\z"
    }, 
    {
        "description": "MySQL client command history file", 
        "secretType": "Filename", 
        "value": "\\A\\.?mysql_history\\z"
    }, 
    {
        "description": "PostgreSQL client command history file", 
        "secretType": "Filename", 
        "value": "\\A\\.?psql_history\\z"
    }, 
    {
        "description": "PostgreSQL password file", 
        "secretType": "Filename", 
        "value": "\\A\\.?pgpass\\z"
    }, 
    {
        "description": "Ruby IRB console history file", 
        "secretType": "Filename", 
        "value": "\\A\\.?irb_history\\z"
    }, 
    {
        "description": "Pidgin chat client account configuration file", 
        "secretType": "Filename", 
        "value": "\\.?purple\\/accounts\\.xml\\z"
    }, 
    {
        "description": "Hexchat/XChat IRC client server list configuration file", 
        "secretType": "Filename", 
        "value": "\\.?xchat2?\\/servlist_?\\.conf\\z"
    }, 
    {
        "description": "Irssi IRC client configuration file", 
        "secretType": "Filename", 
        "value": "\\.?irssi\\/config\\z"
    }, 
    {
        "description": "Recon-ng web reconnaissance framework API key database", 
        "secretType": "Filename", 
        "value": "\\.?recon-ng\\/keys\\.db\\z"
    }, 
    {
        "description": "DBeaver SQL database manager configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?dbeaver-data-sources.xml\\z"
    }, 
    {
        "description": "Mutt e-mail client configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?muttrc\\z"
    }, 
    {
        "description": "S3cmd configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?s3cfg\\z"
    }, 
    {
        "description": "AWS CLI credentials file", 
        "secretType": "Filename", 
        "value": "\\.?aws/credentials\\z"
    }, 
    {
        "description": "T command-line Twitter client configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?trc\\z"
    }, 
    {
        "description": "OpenVPN client configuration file", 
        "secretType": "Filename", 
        "value": "\\.ovpn$"
    }, 
    {
        "description": "Well, this is awkward... Gitrob configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?gitrobrc\\z"
    }, 
    {
        "description": "Shell configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?(bash|zsh)rc\\z"
    }, 
    {
        "description": "Shell profile configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?(bash_|zsh_)?profile\\z"
    }, 
    {
        "description": "Shell command alias configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?(bash_|zsh_)?aliases\\z"
    }, 
    {
        "description": "Potential Ruby On Rails database configuration file", 
        "secretType": "Filename", 
        "value": "database.yml"
    }, 
    {
        "description": "PHP configuration file", 
        "secretType": "Filename", 
        "value": "\\A(.*)?config(\\.inc)?\\.php\\z"
    }, 
    {
        "description": "KeePass password manager database file", 
        "secretType": "Filename", 
        "value": "\\.kdb$"
    }, 
    {
        "description": "1Password password manager database file", 
        "secretType": "Filename", 
        "value": "\\.agilekeychain$"
    }, 
    {
        "description": "Apple Keychain database file", 
        "secretType": "Filename", 
        "value": "\\.keychain$"
    }, 
    {
        "description": "GNOME Keyring database file", 
        "secretType": "Filename", 
        "value": "\\Akey(store|ring)\\z"
    }, 
    {
        "description": "Network traffic capture file", 
        "secretType": "Filename", 
        "value": "\\.pcap$"
    }, 
    {
        "description": "SQL dump file", 
        "secretType": "Filename", 
        "value": "\\Asql(dump)?\\z"
    }, 
    {
        "description": "GnuCash database file", 
        "secretType": "Filename", 
        "value": "\\.gnucash$"
    }, 
    {
        "description": "Jenkins publish over SSH plugin file", 
        "secretType": "Filename", 
        "value": "jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml"
    }, 
    {
        "description": "Potential Jenkins credentials file", 
        "secretType": "Filename", 
        "value": "credentials.xml$"
    }, 
    {
        "description": "Apache htpasswd file", 
        "secretType": "Filename", 
        "value": "\\A\\.?htpasswd\\z"
    }, 
    {
        "description": "Configuration file for auto-login process", 
        "secretType": "Filename", 
        "value": "\\A(\\.|_)?netrc\\z"
    }, 
    {
        "description": "KDE Wallet Manager database file", 
        "secretType": "Filename", 
        "value": "\\.kwallet$"
    }, 
    {
        "description": "Potential MediaWiki configuration file", 
        "secretType": "Filename", 
        "value": "LocalSettings.php"
    }, 
    {
        "description": "Tunnelblick VPN configuration file", 
        "secretType": "Filename", 
        "value": "\\.tblk$"
    }, 
    {
        "description": "Rubygems credentials file", 
        "secretType": "Filename", 
        "value": "\\.?gem/credentials\\z"
    }, 
    {
        "description": "Potential MSBuild publish profile", 
        "secretType": "Filename", 
        "value": "\\A*\\.pubxml(\\.user)?\\z"
    }, 
    {
        "description": "Sequel Pro MySQL database manager bookmark file", 
        "secretType": "Filename", 
        "value": "Favorites.plist"
    }, 
    {
        "description": "Little Snitch firewall configuration file", 
        "secretType": "Filename", 
        "value": "configuration.user.xpl"
    }, 
    {
        "description": "Day One journal file", 
        "secretType": "Filename", 
        "value": "\\.dayone$"
    }, 
    {
        "description": "Tugboat DigitalOcean management tool configuration", 
        "secretType": "Filename", 
        "value": "\\A\\.?tugboat\\z"
    }, 
    {
        "description": "git-credential-store helper credentials file", 
        "secretType": "Filename", 
        "value": "\\A\\.?git-credentials\\z"
    }, 
    {
        "description": "Git configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?gitconfig\\z"
    }, 
    {
        "description": "Chef Knife configuration file", 
        "secretType": "Filename", 
        "value": "knife.rb"
    }, 
    {
        "description": "Chef private key", 
        "secretType": "Filename", 
        "value": "\\.?chef/(.*)\\.pem\\z"
    }, 
    {
        "description": "cPanel backup ProFTPd credentials file", 
        "secretType": "Filename", 
        "value": "proftpdpasswd"
    }, 
    {
        "description": "Robomongo MongoDB manager configuration file", 
        "secretType": "Filename", 
        "value": "robomongo.json"
    }, 
    {
        "description": "FileZilla FTP configuration file", 
        "secretType": "Filename", 
        "value": "filezilla.xml"
    }, 
    {
        "description": "FileZilla FTP recent servers file", 
        "secretType": "Filename", 
        "value": "recentservers.xml"
    }, 
    {
        "description": "Ventrilo server configuration file", 
        "secretType": "Filename", 
        "value": "ventrilo_srv.ini"
    }, 
    {
        "description": "Docker configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?dockercfg\\z"
    }, 
    {
        "description": "NPM configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?npmrc\\z"
    }, 
    {
        "description": "Terraform variable config file", 
        "secretType": "Filename", 
        "value": "terraform.tfvars"
    }, 
    {
        "description": "Environment configuration file", 
        "secretType": "Filename", 
        "value": "\\A\\.?env\\z"
    }, 
    {
        "description": "Secret", 
        "secretType": "FileContent", 
        "value": "(\\n[a-z0-9_\\-]+[:;\\|][a-z0-9_\\-]+){10,}"
    }, 
    {
        "description": "API secret key", 
        "secretType": "FileContent", 
        "value": "(api|secret)key\\s*[\\=]+"
    }, 
    {
        "description": "iCalender", 
        "secretType": "FileContent", 
        "value": "BEGIN:VCALENDAR"
    }, 
    {
        "description": "secret key", 
        "secretType": "FileContent", 
        "value": "\\s*[a-z0-9\\-_]*secret[key]+\\s*[:=]+\\s*[\"']\\S+[\"']"
    }, 
    {
        "description": "HtPasswds", 
        "secretType": "FileContent", 
        "value": "^[a-z0-9]+:[a-z0-9]{13}$"
    }, 
    {
        "description": "Secret finder", 
        "secretType": "FileContent", 
        "value": "secret\\s*[\\=]+"
    }
]
`)