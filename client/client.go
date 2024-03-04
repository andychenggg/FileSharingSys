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
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

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

// SECTION I: SELF-DEFINE STRUCTS AND CONST

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
	Start   []byte
	Counter int
}

type FilePiece []byte

type ShareInfo struct {
	FileSymKey    []byte
	FileLocSymKey []byte
	uuidBranch    uuid.UUID
}

type InvitationGraph map[string]uuid.UUID

type DatastoreGetError struct {
	Msg string
}

func (e *DatastoreGetError) Error() string {
	return fmt.Sprintf("DatastoreGet error: %s", e.Msg)
}

type HmacCheckError struct {
	Msg string
}

func (e *HmacCheckError) Error() string {
	return fmt.Sprintf("Hmac error: %s", e.Msg)
}

// SECTION II: LOCAL VARIABLES

var curUser User

// SECTION III: HELPER FUNCTIONS

func getUuidFromUsername(username string) (id uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(username))[:16])
}

func ValidateUser(username string, exist bool) (valid bool) {
	userUUID, err := getUuidFromUsername(username)
	if err == nil {
		_, ok := userlib.DatastoreGet(userUUID)
		return ok == exist
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

func EncSymKeyGen(SymKey []byte) (derivedKey []byte, err error) {
	return userlib.HashKDF(SymKey, []byte("EncSymKey"))
}

func HmacKeyGen(SymKey []byte) (derivedKey []byte, err error) {
	return userlib.HashKDF(SymKey, []byte("HmacKey"))
}

func DatastoreSet(encKey []byte, hmacKey []byte, address uuid.UUID, v interface{}) (err error) {
	userBytes, MarshalErr := json.Marshal(v)
	if MarshalErr != nil {
		return MarshalErr
	}
	userBytes = userlib.SymEnc(encKey, userlib.RandomBytes(16), userBytes)
	hmacUb, HMACEvalErr := userlib.HMACEval(hmacKey, userBytes)
	if HMACEvalErr != nil {
		return HMACEvalErr
	}
	userBytes = append(userBytes, hmacUb...)
	userlib.DatastoreSet(address, userBytes)
	return nil
}

func DatastoreGet(decKey []byte, hmacKey []byte, address uuid.UUID, obj interface{}) (err error) {
	value, ok := userlib.DatastoreGet(address)
	if !ok {
		return &DatastoreGetError{"invalid address"}
	}
	// INFO: check the hmac
	temp, hmacErr := userlib.HMACEval(hmacKey, value[:len(value)-64])
	if hmacErr != nil {
		return hmacErr
	}
	hmacEqual := userlib.HMACEqual(temp, value[len(value)-64:])
	if !hmacEqual {
		return &HmacCheckError{"integrity check fails"}
	}
	// INFO: decrypt data
	userBytes := userlib.SymDec(decKey, value[len(value)-64:])
	// INFO: unmarshal data
	unmarshalErr := json.Unmarshal(userBytes, obj)
	if unmarshalErr != nil {
		return unmarshalErr
	}

	return nil
}

func AddressOfUUIDFileGen(username string, filename string) (id uuid.UUID, err error) {
	// INFO: calculate the uid
	uid, fromBytesErr := uuid.FromBytes(
		userlib.Hash(
			append(
				userlib.Hash([]byte(username)), userlib.Hash([]byte(filename))...,
			),
		)[:16],
	)
	if fromBytesErr != nil {
		return uid, fromBytesErr
	}
	return uid, nil
}

func getUUIDFromStartAndIndex(start []byte, index int) (id uuid.UUID, err error) {
	res := userlib.Hash(append(
		start, []byte(strconv.Itoa(index))...,
	))
	return uuid.FromBytes(userlib.Hash(res)[:16])
}

func InitUUIDFile(id uuid.UUID, decKey []byte, verKey []byte) (uf *UUIDFile, addOfFileHead *uuid.UUID, fh *FileHead, err error) {
	// INFO: create a UUIDFile and store it
	uf.UUID = uuid.New()
	uf.SymKey = userlib.RandomBytes(16)
	dataStoreSetErr := DatastoreSet(decKey, verKey, id, *uf)
	if dataStoreSetErr != nil {
		return nil, nil, nil, dataStoreSetErr
	}
	// INFO: key generations
	encKey, encKeyErr := EncSymKeyGen(uf.SymKey)
	if encKeyErr != nil {
		return nil, nil, nil, encKeyErr
	}
	hmacKey, hmacKeyErr := HmacKeyGen(uf.SymKey)
	if hmacKeyErr != nil {
		return nil, nil, nil, hmacKeyErr
	}
	// INFO: store the address of the FileHead in the uf.UUID
	*addOfFileHead = uuid.New()
	dataStoreSetErr = DatastoreSet(encKey, hmacKey, uf.UUID, addOfFileHead)
	if dataStoreSetErr != nil {
		return nil, nil, nil, dataStoreSetErr
	}
	// INFO: init a FileHead
	*fh = FileHead{Start: userlib.RandomBytes(16), Counter: 0}
	dataStoreSetErr = DatastoreSet(encKey, hmacKey, *addOfFileHead, fh)
	if dataStoreSetErr != nil {
		return nil, nil, nil, dataStoreSetErr
	}
	return uf, addOfFileHead, fh, nil
}

func GetUUIDFile(id uuid.UUID, decKey []byte, verKey []byte) (uf *UUIDFile, addOfFileHead *uuid.UUID, fh *FileHead, err error) {
	// INFO: get and check the integrity of the existed one
	datastoreGetErr := DatastoreGet(decKey, verKey, id, uf)
	if datastoreGetErr != nil {
		return nil, nil, nil, err
	}
	// INFO: key generations
	encKey, encKeyErr := EncSymKeyGen(uf.SymKey)
	if encKeyErr != nil {
		return nil, nil, nil, encKeyErr
	}
	hmacKey, hmacKeyErr := HmacKeyGen(uf.SymKey)
	if hmacKeyErr != nil {
		return nil, nil, nil, hmacKeyErr
	}
	// INFO: get the uuid -> FileHead by querying uuid -> uuid -> FileHead and check integrity
	datastoreGetErr = DatastoreGet(encKey, hmacKey, (*uf).UUID, addOfFileHead)
	if datastoreGetErr != nil {
		return nil, nil, nil, err
	}
	// INFO: get the FileHead by querying uuid -> FileHead
	datastoreGetErr = DatastoreGet(encKey, hmacKey, *addOfFileHead, fh)
	if datastoreGetErr != nil {
		return nil, nil, nil, err
	}
	return uf, addOfFileHead, fh, nil
}

func ReinitializeFile(addOfFileHead *uuid.UUID, fh *FileHead, encKey []byte, hmacKey []byte) (err error) {
	// INFO: delete the original file first
	for i := 0; i < fh.Counter; i++ {
		id, idErr := getUUIDFromStartAndIndex(fh.Start, i)
		if idErr != nil {
			return idErr
		}
		userlib.DatastoreDelete(id)
	}
	// INFO: reset a new FileHead and then write it back to the database
	fh = &FileHead{
		Start:   userlib.RandomBytes(16),
		Counter: 0,
	}
	datastoreSetErr := DatastoreSet(encKey, hmacKey, *addOfFileHead, fh)
	return datastoreSetErr
}

func AppendContent(aof *uuid.UUID, fh *FileHead, content FilePiece, encKey []byte, hmacKey []byte) (err error) {
	id, idErr := getUUIDFromStartAndIndex(fh.Start, fh.Counter)
	if idErr != nil {
		return idErr
	}
	// INFO: append the content
	datastoreSetErr := DatastoreSet(encKey, hmacKey, id, content)
	if datastoreSetErr != nil {
		return datastoreSetErr
	}
	// INFO: counter++
	fh.Counter++
	datastoreSetErr = DatastoreSet(encKey, hmacKey, *aof, fh)
	return datastoreSetErr
}

func IterateContent(fh *FileHead, fileDecKey []byte, fileHmacKey []byte) (content []byte, err error) {
	// INFO: delete the original file first
	content = make([]byte, 0)
	for i := 0; i < fh.Counter; i++ {
		id, idErr := getUUIDFromStartAndIndex(fh.Start, i)
		if idErr != nil {
			return nil, idErr
		}
		fp := make([]byte, 0)
		dtgErr := DatastoreGet(fileDecKey, fileHmacKey, id, &fp)
		if dtgErr != nil {
			return nil, dtgErr
		}
		content = append(content, fp...)
	}
	return content, nil
}

// SECTION IV: main functions

func InitUser(username string, password string) (userDataPtr *User, err error) {
	var userdata User
	// INFO: validate the username
	valid := ValidateUser(username, false)
	if !valid {
		return nil, &DatastoreGetError{"username exists"}
	}
	// INFO: generate symmetric key for a specific (password, username)
	userdata.Username = username
	userdata.SymKey = PasswordGenSymKey(password, username)
	// INFO: generate public-private keys for encryption
	pub, pri, PKEKeyGenErr := userlib.PKEKeyGen()
	if PKEKeyGenErr != nil {
		return nil, PKEKeyGenErr
	}
	userdata.DecKey = pri
	KeystoreSetErr := userlib.KeystoreSet(EncKeyNameOfUser(username), pub)
	if KeystoreSetErr != nil {
		return nil, KeystoreSetErr
	}
	// INFO: generate keys pairs for signatures
	sign, ver, DSKeyGenErr := userlib.DSKeyGen()
	if DSKeyGenErr != nil {
		return nil, DSKeyGenErr
	}
	userdata.SignKey = sign
	KeystoreSetErr = userlib.KeystoreSet(VerKeyNameOfUser(username), ver)
	if KeystoreSetErr != nil {
		return nil, KeystoreSetErr
	}
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return nil, UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return nil, UserHmacKeyErr
	}
	// INFO: encrypt-then-hmac the data and write it into the datastore
	uuidFromUsername, uuidErr := getUuidFromUsername(username)
	if uuidErr != nil {
		return nil, uuidErr
	}
	datastoreSetErr := DatastoreSet(userEncSymKey, userHmacKey, uuidFromUsername, &userdata)
	if datastoreSetErr != nil {
		return nil, datastoreSetErr
	}
	// INFO: store userdata in local var
	curUser = userdata

	return &userdata, nil
}

func GetUser(username string, password string) (userDataPtr *User, err error) {
	var userdata User
	// INFO: validate the username
	valid := ValidateUser(username, true)
	if !valid {
		return nil, &DatastoreGetError{"username not found"}
	}
	// INFO: generate symmetric key for a specific (password, username)
	userdata.SymKey = PasswordGenSymKey(password, username)
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return nil, UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return nil, UserHmacKeyErr
	}
	// INFO: get data from store
	uuidFromUsername, uuidErr := getUuidFromUsername(username)
	if uuidErr != nil {
		return nil, uuidErr
	}
	userDataPtr = &userdata
	datastoreErr := DatastoreGet(
		userEncSymKey, userHmacKey, uuidFromUsername, userDataPtr,
	)
	if datastoreErr != nil {
		return nil, datastoreErr
	}
	// INFO: store userdata in local var
	curUser = userdata

	return userDataPtr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, addGenErr := AddressOfUUIDFileGen(userdata.Username, filename)
	if addGenErr != nil {
		return addGenErr
	}
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return UserHmacKeyErr
	}
	// INFO: Init or get the file structure
	_, ok := userlib.DatastoreGet(storageKey)
	var uf *UUIDFile
	var aof *uuid.UUID
	var fh *FileHead
	if !ok {
		// INFO: create a new file
		uf, aof, fh, err = InitUUIDFile(storageKey, userEncSymKey, userHmacKey)
		if err != nil {
			return err
		}
	} else {
		// INFO: get the current one
		uf, aof, fh, err = GetUUIDFile(storageKey, userEncSymKey, userHmacKey)
		if err != nil {
			return err
		}
	}
	// INFO: generate keys for this file's encryption/decryption and hmac
	fileEncSymKey, fileEncSymKeyErr := EncSymKeyGen(uf.SymKey)
	if fileEncSymKeyErr != nil {
		return fileEncSymKeyErr
	}
	fileHmacKey, fileHmacKeyErr := HmacKeyGen(uf.SymKey)
	if fileHmacKeyErr != nil {
		return fileHmacKeyErr
	}
	// INFO: reinitialize the file if it exists
	err = ReinitializeFile(aof, fh, fileEncSymKey, fileHmacKey)
	if err != nil {
		return err
	}
	// INFO: append content to the file
	appErr := AppendContent(aof, fh, content, fileEncSymKey, fileHmacKey)
	if appErr != nil {
		return appErr
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	storageKey, addGenErr := AddressOfUUIDFileGen(userdata.Username, filename)
	if addGenErr != nil {
		return err
	}
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return UserHmacKeyErr
	}
	// INFO: Get the file structure
	_, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return &DatastoreGetError{"file name does not exist in the namespace"}
	} else {
		// INFO: get the file structure
		uf, aof, fh, err := GetUUIDFile(storageKey, userEncSymKey, userHmacKey)
		if err != nil {
			return err
		}
		// INFO: generate keys for this file's encryption/decryption and hmac
		fileEncSymKey, fileEncSymKeyErr := EncSymKeyGen(uf.SymKey)
		if fileEncSymKeyErr != nil {
			return fileEncSymKeyErr
		}
		fileHmacKey, fileHmacKeyErr := HmacKeyGen(uf.SymKey)
		if fileHmacKeyErr != nil {
			return fileHmacKeyErr
		}
		err = AppendContent(aof, fh, content, fileEncSymKey, fileHmacKey)
		return err
	}
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, addGenErr := AddressOfUUIDFileGen(userdata.Username, filename)
	if addGenErr != nil {
		return nil, err
	}
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return nil, UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return nil, UserHmacKeyErr
	}
	// INFO: Get the file structure
	_, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, &DatastoreGetError{"file name does not exist in the namespace"}
	} else {
		// INFO: get the file structure
		uf, _, fh, err := GetUUIDFile(storageKey, userEncSymKey, userHmacKey)
		if err != nil {
			return nil, err
		}
		// INFO: generate keys for this file's encryption/decryption and hmac
		fileEncSymKey, fileEncSymKeyErr := EncSymKeyGen(uf.SymKey)
		if fileEncSymKeyErr != nil {
			return nil, fileEncSymKeyErr
		}
		fileHmacKey, fileHmacKeyErr := HmacKeyGen(uf.SymKey)
		if fileHmacKeyErr != nil {
			return nil, fileHmacKeyErr
		}
		content, err = IterateContent(fh, fileEncSymKey, fileHmacKey)
		if err != nil {
			return nil, err
		}
		return content, nil
	}
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
