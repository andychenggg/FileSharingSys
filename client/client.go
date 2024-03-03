package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).

// SECTION I: SELF-DEFINE STRUCTS

type User struct {
	Username string
	SymKey   []byte
	DecKey   userlib.PKEDecKey
	SignKey  userlib.DSSignKey
}

type UUIDFile struct {
	UUID   uuid.UUID
	SymKey []byte
}

type FileHead struct {
	Start   uuid.UUID
	Counter int
}

type FilePiece string

type ShareInfo struct {
	FileSymKey    []byte
	FileLocSymKey []byte
	uuidBranch    uuid.UUID
}

type InvitationGraph map[string]uuid.UUID

// SECTION II: HELPER FUNCTIONS

func getUuidFromUsername(username string) (id uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(username))[:16])
}

func ValidateUserInitialization(username string) (valid bool) {
	userUUID, err := getUuidFromUsername(username)
	if err == nil {
		_, ok := userlib.DatastoreGet(userUUID)
		return !ok
	}
	return false
}

func PasswordGenSymKey(password string, username string) (SymKey []byte) {
	//remark: the length is 16 bytes
	return userlib.Argon2Key([]byte(password), []byte(username), 16)
}

func EncKeyNameOfUser(username string) (EncKeyName string) {
	return username + "EncKey"
}

func VerKeyNameOfUser(username string) (VerKeyName string) {
	return username + "VerKey"
}

func UserEncSymKey(SymKey []byte) (derivedKey []byte, err error) {
	return userlib.HashKDF(SymKey, []byte("UserEncSymKey"))
}

func UserHmacKey(SymKey []byte) (derivedKey []byte, err error) {
	return userlib.HashKDF(SymKey, []byte("UserHmacKey"))
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userDataPtr *User, err error) {
	var userdata User
	valid := ValidateUserInitialization(username)
	if !valid {
		return nil, errors.New("invalid username")
	}

	userdata.Username = username
	userdata.SymKey = PasswordGenSymKey(password, username)

	pub, pri, PKEKeyGenErr := userlib.PKEKeyGen()
	if PKEKeyGenErr != nil {
		return nil, PKEKeyGenErr
	}
	userdata.DecKey = pri
	KeystoreSetErr := userlib.KeystoreSet(EncKeyNameOfUser(username), pub)
	if KeystoreSetErr != nil {
		return nil, KeystoreSetErr
	}

	sign, ver, DSKeyGenErr := userlib.DSKeyGen()
	if DSKeyGenErr != nil {
		return nil, DSKeyGenErr
	}
	userdata.SignKey = sign
	KeystoreSetErr = userlib.KeystoreSet(VerKeyNameOfUser(username), ver)
	if KeystoreSetErr != nil {
		return nil, KeystoreSetErr
	}

	userEncSymKey, UserEncSymKeyErr := UserEncSymKey(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return nil, UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := UserHmacKey(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return nil, UserHmacKeyErr
	}
	userBytes, MarshalErr := json.Marshal(&userdata)
	if MarshalErr != nil {
		return nil, MarshalErr
	}
	uuidFromUsername, _ := getUuidFromUsername(username)
	userBytes = userlib.SymEnc(userEncSymKey, userlib.RandomBytes(16), userBytes)
	hmacUb, _ := userlib.HMACEval(userHmacKey, userBytes)
	userBytes = append(userBytes, hmacUb...)
	userlib.DatastoreSet(uuidFromUsername, userBytes)

	return &userdata, nil
}

func GetUser(username string, password string) (userDataPtr *User, err error) {
	var userdata User
	userDataPtr = &userdata
	return userDataPtr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
