package main

import (
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
	Size  int 		`json:"size"`
}

type Names struct {
	Country 	string `json:"C"`
	State		string `json:"ST"`
	Location	string	`json:"L"`
	Org			string `json:"O"`
	OU			string `json:"OU"`
}

func CreateCertConfig(cert Cert, certmode string) {
  
    // fmt package implements formatted 
    // I/O and has functions like Printf
    // and Scanf
    fmt.Printf("Gerenrating Openssl Config.....\n")
      
    // in case an error is thrown it is received 
    // by the err variable and Fatalf method of 
    // log prints the error message and stops 
    // program execution
    file, err := os.Create("../openssl.cnf")
      
    if err != nil {
		fmt.Printf("Failed writing to file: %s", err)
    }
      
    // Defer is used for purposes of cleanup like 
    // closing a running file after the file has 
    // been written and main //function has 
    // completed execution
	defer file.Close()
	
	caconf := `	# NOT FOR PRODUCTION USE. OpenSSL configuration file for testing.
	
	# For the CA policy
	[ policy_match ]
	countryName = match
	stateOrProvinceName = match
	organizationName = match
	organizationalUnitName = optional
	commonName = `+cert.CN +`
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
	countryName = Country Name (2 letter code)
	countryName_default =
	countryName_min = 2
	countryName_max = 2
	
	stateOrProvinceName = State or Province Name (full name)
	stateOrProvinceName_default = TestCertificateStateName
	stateOrProvinceName_max = 64
	localityName = Locality Name (eg, city)
	localityName_default = `+cert.Names.Location+`
	localityName_max = 64
	
	organizationName = Organization Name (eg, company)
	organizationName_default = `+cert.Names.Org+`
	organizationName_max = 64
	
	organizationalUnitName = Organizational Unit Name (eg, section)
	organizationalUnitName_default = `+cert.Names.OU+`
	organizationalUnitName_max = 64
	
	commonName = Common Name (eg, YOUR name)
	commonName_max = 64
	
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
    fmt.Printf("\nFile Name: %s", file.Name())
    fmt.Printf("\nLength: %d bytes", len)
}

func main(){

	// Open our jsonFile
	jsonFile, err := os.Open("../ca.json")

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

	CreateCertConfig(cert,string("CA"))

}

	