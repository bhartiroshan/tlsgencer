package main

import (
	"bytes"
	"os/exec"
	"io/ioutil"
	"os"
	"fmt"
	"encoding/json"
)

//Struct to parse server.json objects
type Cert struct {
    CN   	string 		`json:"CN"`
    Hosts   []string 	`json:"Hosts"`
    IPs    	[]string    `json:"IPs"`
	Key 	Key 		`json:"Key"`
	Names 	Names 		`json:"Names"`
}

type Key struct {
	Algo  string 	`json:"algo"`
	Size  string 		`json:"size"`
}

type Names struct {
	Country 	string `json:"C"`
	State		string `json:"ST"`
	Location	string	`json:"L"`
	Org			string `json:"O"`
	OU			string `json:"OU"`
}

func CreateCACerts(cert Cert,certtype string) {

    // fmt package implements formatted 
    // I/O and has functions like Printf
    // and Scanf
    fmt.Printf("Gerenrating Openssl Config.....\n")
      
    // in case an error is thrown it is received 
    // by the err variable and Fatalf method of 
    // log prints the error message and stops 
    // program execution
    file, err := os.Create("openssl-"+certtype+".cnf")
      
    if err != nil {
		fmt.Printf("Failed writing to file: %s", err)
    }
      
    // Defer is used for purposes of cleanup like 
    // closing a running file after the file has 
    // been written and main //function has 
    // completed execution
	defer file.Close()
	
	caconf := `	# NOT FOR PRODUCTION USE. OpenSSL configuration file for testing.
	[req]
	prompt = no
	distinguished_name = req_distinguished_name
	req_extensions = v3_req
	# For the CA policy
	[ policy_match ]
	countryName = match
	stateOrProvinceName = match
	organizationName = match
	organizationalUnitName = optional
	commonName = match
	emailAddress = optional
	
	[ req ]
	default_bits = 4096
	default_keyfile = myTestCertificateKey.pem    ## The default private key file name.
	default_md = sha256                           ## Use SHA-256 for Signatures
	distinguished_name = req_dn
	req_extensions = v3_req
	x509_extensions = v3_ca # The extentions to add to the self signed cert
	
	[ v3_req ]
	subjectKeyIdentifier  = hash
	basicConstraints = CA:FALSE
	keyUsage = critical, digitalSignature, keyEncipherment
	nsComment = "OpenSSL Generated Certificate for TESTING only.  NOT FOR PRODUCTION USE."
	extendedKeyUsage  = serverAuth, clientAuth
	
	[ req_dn ]
	countryName =` +cert.Names.Country+`

	stateOrProvinceName =` +cert.Names.Location+`

	localityName =` +cert.Names.Location+`

	organizationName =` +cert.Names.Org+`
	
	organizationalUnitName =` +cert.Names.OU+`
	
	commonName =` +cert.CN+`
	
	[ v3_ca ]
	# Extensions for a typical CA
	
	subjectKeyIdentifier=hash
	basicConstraints = critical,CA:true
	authorityKeyIdentifier=keyid:always,issuer:always`

	len, err := file.WriteString(caconf)

    if err != nil {
        fmt.Printf("failed writing to file: %s", err)
    }
  
    // Name() method returns the name of the 
    // file as presented to Create() method.
	fmt.Printf("\nFile Name: %s created successfully", file.Name())
	fmt.Printf("\nLength: %d bytes written", len)
	fmt.Printf("\n Generating %s key of length %s",certtype,cert.Key.Size)
	genKey(cert.Key.Size,certtype)
	
}
func genKey(size string,mode string){

	cmd := exec.Command("openssl", "genrsa","-out","mongodb-test-"+mode+".key",size)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
    if err != nil {
        fmt.Printf("cmd.Run() failed with %s\n", err)
    }
    outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
    fmt.Printf("\n%s\n%s\n", outStr, errStr)	
}

func loadCert(filename string)Cert{
		// Open our jsonFile
		jsonFile, err := os.Open(filename)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}	
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()	
		//JSON File handling
		var cert Cert
		byteValue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(byteValue, &cert)

		return cert
}

// Exists reports whether the named file or directory exists.
func Exists(name string) bool {
    if _, err := os.Stat(name); err != nil {
        if os.IsNotExist(err) {
            return false
        }
    }
    return true
}

//Generate first certificate to sign server certificates
func generateCA(){
	var certCA,certIA Cert
	certCA = loadCert("rootCA.json")
	CreateCACerts(certCA,"CA")
	certIA = loadCert("ca.json")
	CreateCACerts(certIA,"IA")

	//Root CA Certs
	cmd := exec.Command("openssl", "req", "-new", "-x509", "-days", "1826", "-key", "mongodb-test-CA.key", "-out", "mongodb-test-ca.crt", "-config", "openssl-CA.cnf")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
    if err != nil {
        fmt.Printf("cmd.Run() failed with %s\n%s", err,errStr)
    }else{
		fmt.Printf("\nCA Cert generation was successful: mongodb-test-ca.crt %s\n", outStr)
	}

	//Generate IA CSR
	cmd = exec.Command("openssl", "req", "-new", "-key", "mongodb-test-ia.key", "-out", "mongodb-test-ia.csr", "-config", "openssl-IA.cnf")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	outStr, errStr = string(stdout.Bytes()), string(stderr.Bytes())
    if err != nil {
        fmt.Printf("cmd.Run() failed with %s\n%s", err,errStr)
    }else{
		fmt.Printf("\nIA Cert CSR generation was successful:%s\n", outStr)
	}

	//Sign IA Certs
	cmd = exec.Command("openssl", "x509", "-sha256", "-req", "-days", "730", "-in", "mongodb-test-ia.csr", "-CA", "mongodb-test-ca.crt", "-CAkey", "mongodb-test-CA.key", "-set_serial", "01", "-out", "mongodb-test-ia.crt", "-extfile", "openssl-IA.cnf", "-extensions", "v3_ca")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	outStr, errStr = string(stdout.Bytes()), string(stderr.Bytes())
    if err != nil {
        fmt.Printf("cmd.Run() failed with %s\n%s", err,errStr)
    }else{
		fmt.Printf("\nIA Cert generation was successful: mongodb-test-ia.crt%s\n", outStr)
	}
	

}

func main(){

	// Load cert file
	isExistsCA := Exists("tlsgencer-ia.crt")
	if isExistsCA == false {
		fmt.Println("\nNo CA exist to sign certificates, generating CA certs.......")
		generateCA()
	}else{
		fmt.Println("CA certificates exists to sign server certificates, using it to sign certificates.")
	}

}

	