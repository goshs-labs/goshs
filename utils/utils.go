// Package utils has general utility functions
package utils

import (
	"fmt"
	"mime"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/bcrypt"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
)

// ByteCountDecimal generates human readable file sizes and returns a string
func ByteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

// MimeByExtension returns the mimetype string depending on the filename and its extension
func MimeByExtension(n string) string {
	return mime.TypeByExtension(ReturnExt(n))
}

// ReturnExt returns the extension of a filename, including the leading dot.
// It returns an empty string when the name carries no extension.
func ReturnExt(n string) string {
	return filepath.Ext(n)
}

// GetInterfaceIpv4Addr will return the ip address by name
func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipv4Addr = ipNet.IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", fmt.Errorf("interface %s doesn't have an ipv4 address", interfaceName)
	}
	return ipv4Addr.String(), nil
}

// GetAllIPAddresses returns a map of interface name to IPv4 address for all interfaces.
func GetAllIPAddresses() (map[string]string, error) {
	ifaceAddress := make(map[string]string)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		ip, err := GetInterfaceIpv4Addr(i.Name)
		if err != nil {
			continue
		}
		ifaceAddress[i.Name] = ip
	}
	return ifaceAddress, nil
}

// GenerateHashPassword will take a plaintext masked password and return a bcrypt hash
// This is meant to be used with the filebased access via .goshs file
func GenerateHashedPassword(password []byte) string {
	bytes, err := bcrypt.GenerateFromPassword(password, 14)
	if err != nil {
		logger.Fatalf("error hashing password: %+v", err)
	}
	fmt.Printf("Hash: %s\n", string(bytes))

	return string(bytes)
}

func RegisterZeroconfMDNS(ssl bool, webPort int, webdav bool, webdavPort int, smtp bool, smtpPort int, dns bool, dnsPort int, smb bool, smbPort int, ldap bool, ldapPort int, ftp bool, ftpSFTPMode bool, ftpPort int, tftp bool, tftpPort int) error {
	// Register zeroconf mDNS
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("cannot get hostname for mDNS: %+v", err)
	}
	// Remove duplicate .local if applicable
	hostname = strings.TrimSuffix(hostname, ".local")
	// Register webPort
	var serviceType string
	var out string
	switch ssl {
	case true:
		serviceType = "_https._tcp"
		out = "https"
	default:
		serviceType = "_http._tcp"
		out = "http"
	}
	zero, err := zeroconf.Register(
		"goshs WebInterface",
		serviceType,
		"local.",
		webPort,
		[]string{fmt.Sprintf("host=%s.local", hostname), "path=/", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
		nil,
	)
	if err != nil {
		return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
	}
	defer zero.Shutdown()

	logger.Infof("mDNS service registered as %s://%s.local:%d", out, hostname, webPort)

	// Register webdav if enabled
	if webdav {
		switch ssl {
		case true:
			serviceType = "_webdavs._tcp"
			out = "webdavs"
		default:
			serviceType = "_webdav._tcp"
			out = "webdav"
		}

		zeroDav, err := zeroconf.Register(
			"goshs WebDAV",
			serviceType,
			"local.",
			webdavPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), "path=/", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDNS service registered as %s://%s.local:%d", out, hostname, webdavPort)
	}

	// Register smtp if enabled
	if smtp {
		zeroDav, err := zeroconf.Register(
			"goshs SMTP",
			"_smtp._tcp",
			"local.",
			smtpPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), "auth=false", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDNS service registered as smtp://%s.local:%d", hostname, smtpPort)
	}

	// Register dns if enabled
	if dns {
		zeroDav, err := zeroconf.Register(
			"goshs DNS",
			"_dns._udp",
			"local.",
			dnsPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDNS service registered as dns://%s.local:%d", hostname, dnsPort)
	}

	// Register smb if enabled
	if smb {
		zeroDav, err := zeroconf.Register(
			"goshs SMB",
			"_smb._tcp",
			"local.",
			smbPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDNS service registered as smb://%s.local:%d", hostname, smbPort)
	}

	// Register ldap if enabled
	if ldap {
		zeroDav, err := zeroconf.Register(
			"goshs LDAP",
			"_ldap._tcp",
			"local.",
			ldapPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDNS service registered as ldap://%s.local:%d", hostname, ldapPort)
	}

	// Register ftp/sftp if enabled
	if ftp {
		var ftpServiceType, ftpProto, ftpName string
		var ftpTxtRecords []string
		if ftpSFTPMode {
			ftpServiceType = "_ssh._tcp"
			ftpProto = "ssh"
			ftpName = "goshs SFTP"
			ftpTxtRecords = []string{fmt.Sprintf("host=%s.local", hostname), "subsystem=sftp", "path=/", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)}
		} else {
			ftpServiceType = "_ftp._tcp"
			ftpProto = "ftp"
			ftpName = "goshs FTP"
			ftpTxtRecords = []string{fmt.Sprintf("host=%s.local", hostname), fmt.Sprintf("version=%s", goshsversion.GoshsVersion)}
		}
		zeroFTP, err := zeroconf.Register(
			ftpName,
			ftpServiceType,
			"local.",
			ftpPort,
			ftpTxtRecords,
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroFTP.Shutdown()

		logger.Infof("mDNS service registered as %s://%s.local:%d", ftpProto, hostname, ftpPort)
	}

	// Register tftp if enabled
	if tftp {
		zeroTFTP, err := zeroconf.Register(
			"goshs TFTP",
			"_tftp._udp",
			"local.",
			tftpPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroTFTP.Shutdown()

		logger.Infof("mDNS service registered as tftp://%s.local:%d", hostname, tftpPort)
	}

	return nil
}
