package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt"
)

type stat struct {
	AuthVisit            int
	VerifyVisit          int
	TotalDecodeTime      int64
	TotalDecodeTimeCount int
	TotalEncodeTime      int64
	TotalEncodeTimeCount int
}

var privateKey *rsa.PrivateKey
var publickKeyStr string

// Import the private public key pair into the global privateKey object
func getPrivPub() {
	priv, err := ioutil.ReadFile("private.pem")
	privPem, _ := pem.Decode(priv)
	if privPem.Type != "RSA PRIVATE KEY" {
		fmt.Printf("RSA private key is of the wrong type: %s", privPem)
	}

	var privPemBytes []byte

	privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte("pempassword"))
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			fmt.Printf("Unable to parse RSA private key, generating a temp one %s", err)
		}
	}

	var privKey *rsa.PrivateKey
	var ok bool
	privKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Printf("Unable to parse RSA private key, generating a temp one %s", err)
	}

	pub, err := ioutil.ReadFile("public.pem")
	if err != nil {
		fmt.Printf("No RSA public key found, generating temp one")
	}

	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		fmt.Printf("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key")
	}

	if pubPem.Type != "PUBLIC KEY" {
		fmt.Printf("RSA public key is of the wrong type: %s", privPem.Type)
	}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		fmt.Printf("Unable to parse RSA public key, generating a temp one: %s\n", err)
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		fmt.Printf("Unable to parse RSA public key, generating a temp one: %s\n", err)
	}

	publickKeyStr = string(pub)

	privKey.PublicKey = *pubKey
	privateKey = privKey
}

// Read from Stat JSON file
func readStatFile() stat {
	bytes, err := ioutil.ReadFile("stats.json")

	if err != nil {
		return stat{}
	}

	stats := &stat{}
	json.Unmarshal([]byte(bytes), stats)

	return *stats
}

// Write to Stat JSON file
func writeStatFile(stats stat) {
	marshalled, _ := json.Marshal(&stats)
	ioutil.WriteFile("stats.json", marshalled, 0644)
}

// Generate a JWT
func createToken(username string) (token string, err error) {
	start := time.Now()

	atExpires := time.Now().Add(time.Hour * 24).Unix()
	atClaims := jwt.MapClaims{}
	atClaims["sub"] = username
	atClaims["exp"] = atExpires
	at := jwt.NewWithClaims(jwt.SigningMethodRS256, atClaims)
	token, err = at.SignedString(privateKey)

	elapsed := time.Since(start).Microseconds()
	stats := readStatFile()

	stats.TotalEncodeTime += elapsed
	stats.TotalEncodeTimeCount += 1

	writeStatFile(stats)

	fmt.Println(elapsed)
	return token, err
}

// The main driver function
func main() {
	getPrivPub()
	r := chi.NewRouter()

	// A base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/auth/{username}", authenticate)

	r.Get("/verify", verify)

	r.Get("/README.txt", sendReadme)

	r.Get("/stats", sendStats)

	http.ListenAndServe(":3333", r)
}

// Handler for /auth/<username> route
func authenticate(w http.ResponseWriter, r *http.Request) {
	stats := readStatFile()

	stats.AuthVisit += 1

	writeStatFile(stats)

	// Get the username
	username := chi.URLParam(r, "username")

	// Create the token
	token, err := createToken(username)

	if err != nil {
		fmt.Println(err)
	}

	// Add the httponly cookie
	c := http.Cookie{
		Name:     "token",
		Value:    token,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, &c)

	w.Write([]byte(fmt.Sprintf("%s", publickKeyStr)))
}

// Check if the token is valid
func verify(w http.ResponseWriter, r *http.Request) {
	stats := readStatFile()

	stats.VerifyVisit += 1

	// Fetch the token from Cookie
	cookie, err := r.Cookie("token")
	tokenString := cookie.Value

	start := time.Now()

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodRSA"
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &privateKey.PublicKey, nil
	})

	elapsed := time.Since(start).Microseconds()

	stats.TotalDecodeTime += elapsed
	stats.TotalDecodeTimeCount += 1

	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	writeStatFile(stats)

	// Send back the username
	claims, _ := token.Claims.(jwt.MapClaims)
	w.Write([]byte(fmt.Sprintf("%s", claims["sub"])))
}

// Send back the contents of the README.txt file
func sendReadme(w http.ResponseWriter, r *http.Request) {
	fileContents, err := ioutil.ReadFile("README.txt")

	if err != nil {
		fmt.Printf("%s", fileContents)
	}

	w.Write([]byte(fmt.Sprintf("%s", fileContents)))
}

// Send back logged stats
func sendStats(w http.ResponseWriter, r *http.Request) {
	stats := readStatFile()
	avgDecodeTime := float64(stats.TotalDecodeTime) / float64(stats.TotalDecodeTimeCount)
	avgEncodeTime := float64(stats.TotalEncodeTime) / float64(stats.TotalEncodeTimeCount)

	w.Write([]byte(fmt.Sprintf("Total auth visits: %d\nTotal verify visits: %d\nAverage Decode Time: %f\nAverage Encode Time: %f", stats.AuthVisit, stats.VerifyVisit, avgDecodeTime, avgEncodeTime)))
}
