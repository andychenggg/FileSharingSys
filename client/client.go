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
	"bytes"
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
	UUID        uuid.UUID
	SymKey      []byte
	CreatorHash []byte
}

type FileHead struct {
	Start   []byte
	Counter int
}

type FilePiece []byte

type ShareInfo struct {
	FileSymKey []byte
	SSInfo     uuid.UUID
}

type SubShareInfo struct {
	UUIDBranch  uuid.UUID
	CreatorHash []byte
}

type InvitationGraph map[string]uuid.UUID

type FileList map[string]bool

type DatastoreGetError struct {
	Msg string
}

func (e *DatastoreGetError) Error() string {
	return fmt.Sprintf("DatastoreGet error: %s", e.Msg)
}

type KeystoreGetError struct {
	Msg string
}

func (e *KeystoreGetError) Error() string {
	return fmt.Sprintf("KeystoreGet error: %s", e.Msg)
}

type HmacCheckError struct {
	Msg string
}

func (e *HmacCheckError) Error() string {
	return fmt.Sprintf("Hmac error: %s", e.Msg)
}

type RSACheckErr struct {
	Msg string
}

func (e *RSACheckErr) Error() string {
	return fmt.Sprintf("RSA signing error: %s", e.Msg)
}

// SECTION II: LOCAL VARIABLES

var curUser User

// SECTION III: HELPER FUNCTIONS

func getUuidFromUsername(username string, start int) (id uuid.UUID, err error) {
	return uuid.FromBytes(userlib.Hash([]byte(username))[start : start+16])
}

func ValidateUser(username string, exist bool) (valid bool) {
	if username == "" {
		return false
	}
	userUUID, err := getUuidFromUsername(username, 0)
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

func PKEncKeyNameOfUser(username string) (EncKeyName string) {
	return username + "EncKey"
}

func DSVerKeyNameOfUser(username string) (VerKeyName string) {
	return username + "VerKey"
}

func EncSymKeyGen(SymKey []byte) (derivedKey []byte, err error) {
	derivedKey, err = userlib.HashKDF(SymKey, []byte("EncSymKey"))
	if err != nil {
		return nil, err
	}
	return derivedKey[:16], nil
}

func HmacKeyGen(SymKey []byte) (derivedKey []byte, err error) {
	derivedKey, err = userlib.HashKDF(SymKey, []byte("HmacKey"))
	if err != nil {
		return nil, err
	}
	return derivedKey[:16], nil
}

func DatastoreSymSet(encKey []byte, signKey []byte, address uuid.UUID, v interface{}) (err error) {
	userBytes, MarshalErr := json.Marshal(v)
	if MarshalErr != nil {
		return MarshalErr
	}
	userBytes = userlib.SymEnc(encKey, userlib.RandomBytes(16), userBytes)
	hmacUb, HMACEvalErr := userlib.HMACEval(signKey, userBytes)
	if HMACEvalErr != nil {
		return HMACEvalErr
	}
	userBytes = append(userBytes, hmacUb...)
	userlib.DatastoreSet(address, userBytes)
	return nil
}

func DatastoreAsySet(encKey userlib.PKEEncKey, signKey userlib.DSSignKey, address uuid.UUID, v interface{}) (err error) {
	userBytes, MarshalErr := json.Marshal(v)
	if MarshalErr != nil {
		return MarshalErr
	}
	userBytes, err = userlib.PKEEnc(encKey, userBytes)
	if err != nil {
		return err
	}
	signature, err := userlib.DSSign(signKey, userBytes)
	if err != nil {
		return err
	}
	userBytes = append(userBytes, signature...)
	userlib.DatastoreSet(address, userBytes)
	return nil
}

func DatastoreSymGet(decKey []byte, verKey []byte, address uuid.UUID, obj interface{}) (err error) {
	value, ok := userlib.DatastoreGet(address)
	if !ok {
		return &DatastoreGetError{"invalid address"}
	}
	// INFO: check the hmac
	temp, hmacErr := userlib.HMACEval(verKey, value[:len(value)-64])
	if hmacErr != nil {
		return hmacErr
	}
	hmacEqual := userlib.HMACEqual(temp, value[len(value)-64:])
	if !hmacEqual {
		return &HmacCheckError{"integrity check fails"}
	}
	// INFO: decrypt data
	userBytes := userlib.SymDec(decKey, value[:len(value)-64])
	// INFO: unmarshal data
	unmarshalErr := json.Unmarshal(userBytes, obj)
	if unmarshalErr != nil {
		return unmarshalErr
	}

	return nil
}

func DatastoreAsyGet(decKey userlib.PKEDecKey, verKey userlib.DSVerifyKey, address uuid.UUID, obj interface{}) (err error) {
	value, ok := userlib.DatastoreGet(address)
	if !ok {
		return &DatastoreGetError{"invalid address"}
	}
	// INFO: check the hmac
	err = userlib.DSVerify(verKey, value[:len(value)-256], value[len(value)-256:])
	if err != nil {
		return &RSACheckErr{"integrity check fails"}
	}
	// INFO: decrypt data
	userBytes, err := userlib.PKEDec(decKey, value[:len(value)-256])
	// INFO: unmarshal data
	if err != nil {
		return err
	}
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

func InitUUIDFile(id uuid.UUID, decKey []byte, verKey []byte, username string) (uf *UUIDFile, addOfFileHead *uuid.UUID, fh *FileHead, err error) {
	// INFO: Initialization
	uf = new(UUIDFile)
	addOfFileHead = new(uuid.UUID)
	fh = new(FileHead)
	// INFO: create a UUIDFile and store it
	uf.UUID = uuid.New()
	uf.SymKey = userlib.RandomBytes(16)
	uf.CreatorHash = userlib.Hash([]byte(username))[:16]
	dataStoreSetErr := DatastoreSymSet(decKey, verKey, id, *uf)
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
	dataStoreSetErr = DatastoreSymSet(encKey, hmacKey, uf.UUID, addOfFileHead)
	if dataStoreSetErr != nil {
		return nil, nil, nil, dataStoreSetErr
	}
	// INFO: init a FileHead
	*fh = FileHead{Start: userlib.RandomBytes(16), Counter: 0}
	dataStoreSetErr = DatastoreSymSet(encKey, hmacKey, *addOfFileHead, fh)
	if dataStoreSetErr != nil {
		return nil, nil, nil, dataStoreSetErr
	}
	return uf, addOfFileHead, fh, nil
}

func GetUUIDFile(id uuid.UUID, decKey []byte, verKey []byte) (uf *UUIDFile, addOfFileHead *uuid.UUID, fh *FileHead, err error) {
	// INFO: initialization
	uf = new(UUIDFile)
	addOfFileHead = new(uuid.UUID)
	fh = new(FileHead)
	// INFO: get and check the integrity of the existed one
	datastoreGetErr := DatastoreSymGet(decKey, verKey, id, uf)
	if datastoreGetErr != nil {
		return nil, nil, nil, datastoreGetErr
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
	datastoreGetErr = DatastoreSymGet(encKey, hmacKey, (*uf).UUID, addOfFileHead)
	if datastoreGetErr != nil {
		return nil, nil, nil, datastoreGetErr
	}
	// INFO: get the FileHead by querying uuid -> FileHead
	datastoreGetErr = DatastoreSymGet(encKey, hmacKey, *addOfFileHead, fh)
	if datastoreGetErr != nil {
		return nil, nil, nil, datastoreGetErr
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
	fh.Start = userlib.RandomBytes(16)
	fh.Counter = 0
	datastoreSetErr := DatastoreSymSet(encKey, hmacKey, *addOfFileHead, fh)
	return datastoreSetErr
}

func AppendContent(aof *uuid.UUID, fh *FileHead, content FilePiece, encKey []byte, hmacKey []byte) (err error) {
	id, idErr := getUUIDFromStartAndIndex(fh.Start, fh.Counter)
	if idErr != nil {
		return idErr
	}
	// INFO: append the content
	datastoreSetErr := DatastoreSymSet(encKey, hmacKey, id, content)
	if datastoreSetErr != nil {
		return datastoreSetErr
	}
	// INFO: counter++
	fh.Counter++
	datastoreSetErr = DatastoreSymSet(encKey, hmacKey, *aof, fh)
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
		dtgErr := DatastoreSymGet(fileDecKey, fileHmacKey, id, &fp)
		if dtgErr != nil {
			return nil, dtgErr
		}
		content = append(content, fp...)
	}
	return content, nil
}

func UUIDOfInvitationGraph(username string, filename string) (id uuid.UUID, err error) {
	return uuid.FromBytes(
		userlib.Hash(
			append(
				userlib.Hash([]byte(username)), userlib.Hash([]byte(filename))...,
			),
		)[16:32],
	)
}

func moveFileHead(fileEncKey []byte, fileHmacKey []byte, orgId uuid.UUID, newId uuid.UUID) (err error) {
	// INFO: get the file head
	var fh = new(FileHead)
	err = DatastoreSymGet(fileEncKey, fileHmacKey, orgId, fh)
	if err != nil {
		return err
	}
	newStart := userlib.RandomBytes(16)
	for i := 0; i < fh.Counter; i++ {
		// INFO: get the uuid
		id, idErr := getUUIDFromStartAndIndex(fh.Start, i)
		if idErr != nil {
			return idErr
		}
		nid, nidErr := getUUIDFromStartAndIndex(newStart, i)
		if nidErr != nil {
			return nidErr
		}
		// INFO: move the file piece to new place
		var fp = new(FilePiece)
		err = DatastoreSymGet(fileEncKey, fileHmacKey, id, fp)
		if err != nil {
			return err
		}
		err = DatastoreSymSet(fileEncKey, fileHmacKey, nid, fp)
		if err != nil {
			return err
		}
		userlib.DatastoreDelete(id)
	}
	// INFO: replace the start with a new one
	fh.Start = newStart
	// INFO: set the new file head
	err = DatastoreSymSet(fileEncKey, fileHmacKey, newId, fh)
	if err != nil {
		return err
	}
	// INFO: delete the original file head
	userlib.DatastoreDelete(orgId)
	return nil
}

// SECTION IV: main functions

func InitUser(username string, password string) (userDataPtr *User, err error) {
	var userdata User
	// INFO: validate the username
	valid := ValidateUser(username, false)
	if !valid {
		return nil, &DatastoreGetError{"username exists or is empty"}
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
	KeystoreSetErr := userlib.KeystoreSet(PKEncKeyNameOfUser(username), pub)
	if KeystoreSetErr != nil {
		return nil, KeystoreSetErr
	}
	// INFO: generate keys pairs for signatures
	sign, ver, DSKeyGenErr := userlib.DSKeyGen()
	if DSKeyGenErr != nil {
		return nil, DSKeyGenErr
	}
	userdata.SignKey = sign
	KeystoreSetErr = userlib.KeystoreSet(DSVerKeyNameOfUser(username), ver)
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
	uuidFromUsername, uuidErr := getUuidFromUsername(username, 0)
	if uuidErr != nil {
		return nil, uuidErr
	}
	datastoreSetErr := DatastoreSymSet(userEncSymKey, userHmacKey, uuidFromUsername, &userdata)
	if datastoreSetErr != nil {
		return nil, datastoreSetErr
	}
	// INFO: create a file list for an user
	uuidFromUsername, uuidErr = getUuidFromUsername(username, 16)
	if uuidErr != nil {
		return nil, uuidErr
	}
	datastoreSetErr = DatastoreSymSet(userEncSymKey, userHmacKey, uuidFromUsername, FileList{})
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
	uuidFromUsername, uuidErr := getUuidFromUsername(username, 0)
	if uuidErr != nil {
		return nil, uuidErr
	}
	userDataPtr = &userdata
	datastoreErr := DatastoreSymGet(
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
	// INFO: searching the FileList in case that the file have been deleted
	uuidFromUsername, uuidErr := getUuidFromUsername(userdata.Username, 16)
	if uuidErr != nil {
		return uuidErr
	}
	var fl = new(FileList)
	datastoreGetErr := DatastoreSymGet(userEncSymKey, userHmacKey, uuidFromUsername, fl)
	if datastoreGetErr != nil {
		return datastoreGetErr
	}
	_, ok := (*fl)[filename]
	var uf = new(UUIDFile)
	var aof = new(uuid.UUID)
	var fh = new(FileHead)
	// INFO: not in the file list
	if !ok {
		// INFO: insert a new filename in the list
		(*fl)[filename] = true
		datastoreSetErr := DatastoreSymSet(userEncSymKey, userHmacKey, uuidFromUsername, fl)
		if datastoreSetErr != nil {
			return datastoreSetErr
		}
		// INFO: create a new file
		uf, aof, fh, err = InitUUIDFile(storageKey, userEncSymKey, userHmacKey, userdata.Username)
		if err != nil {
			return err
		}
		// INFO: if this guy is the creator, create an invitationGraph
		if bytes.Equal(uf.CreatorHash, userlib.Hash([]byte(userdata.Username))[:16]) {
			id, err := UUIDOfInvitationGraph(userdata.Username, filename)
			if err != nil {
				return err
			}
			err = DatastoreSymSet(userEncSymKey, userHmacKey, id, InvitationGraph{})
			if err != nil {
				return err
			}
		}
	} else {
		// INFO: in the file list -> get the current one
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
		return nil, addGenErr
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

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	/*
		FLow:
		1. check whether an invitation graph exists. If not, create one
		2.
	*/
	// INFO: check whether the user exists
	valid := ValidateUser(recipientUsername, true)
	if !valid {
		return uuid.New(), &DatastoreGetError{"the user does not exist"}
	}
	// INFO: check the current user with filename
	uid, err := AddressOfUUIDFileGen(userdata.Username, filename)
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return uuid.New(), UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return uuid.New(), UserHmacKeyErr
	}

	// INFO: retrieve the file from the ds
	uf, aof, _, err := GetUUIDFile(uid, userEncSymKey, userHmacKey)
	if err != nil {
		return uuid.New(), err
	}
	// INFO: key generations
	fileEncKey, encKeyErr := EncSymKeyGen(uf.SymKey)
	if encKeyErr != nil {
		return uuid.New(), encKeyErr
	}
	fileHmacKey, hmacKeyErr := HmacKeyGen(uf.SymKey)
	if hmacKeyErr != nil {
		return uuid.New(), hmacKeyErr
	}
	// INFO: check whether this guy is the creator
	var uuidBranch uuid.UUID
	if bytes.Equal(uf.CreatorHash, userlib.Hash([]byte(userdata.Username))[:16]) {
		// INFO: is creator
		// INFO: check whether an invitation graph exists.
		id, err := UUIDOfInvitationGraph(userdata.Username, filename)
		if err != nil {
			return uuid.New(), err
		}
		// INFO: get the invitation graph
		ig := new(InvitationGraph)
		err = DatastoreSymGet(userEncSymKey, userHmacKey, id, ig)
		if err != nil {
			return uuid.New(), err
		}
		// INFO: insert a username:uuidBranch pair
		uuidBranch = uuid.New()
		(*ig)[recipientUsername] = uuidBranch
		// INFO: let uuidBranch point to the fileHead
		err = DatastoreSymSet(fileEncKey, fileHmacKey, uuidBranch, *aof)
		if err != nil {
			return uuid.New(), err
		}
		// INFO: write back the ig to ds
		err = DatastoreSymSet(userEncSymKey, userHmacKey, id, ig)
		if err != nil {
			return uuid.New(), err
		}
	} else {
		// INFO: not the creator
		// INFO: let the uuidBranch same as the uf.UUID
		uuidBranch = uf.UUID
	}
	// INFO: initialize the invitationPtr
	invitationPtr = uuid.New()
	// INFO: initialize the ptr for SubShareInfo
	ssiUid := uuid.New()
	// INFO: initialize the shareInfo
	sfo := &ShareInfo{FileSymKey: uf.SymKey, SSInfo: ssiUid}
	//sfo := &ShareInfo{FileSymKey: uf.SymKey, UUIDBranch: uuidBranch}
	// INFO: retrieve the PKEncKey of the recipient
	value, ok := userlib.KeystoreGet(PKEncKeyNameOfUser(recipientUsername))
	if !ok {
		return uuid.New(), &KeystoreGetError{fmt.Sprintf("cannot find %s's PKEncKey", recipientUsername)}
	}
	// INFO: store the shareInfo
	err = DatastoreAsySet(value, userdata.SignKey, invitationPtr, sfo)
	if err != nil {
		return uuid.New(), err
	}
	// INFO: initialize the SubShareInfo
	ssi := &SubShareInfo{UUIDBranch: uuidBranch, CreatorHash: uf.CreatorHash}
	// INFO: store the SubShareInfo, which is encrypted by specified sym-key
	err = DatastoreSymSet(fileEncKey, fileHmacKey, ssiUid, ssi)
	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	// INFO: retrieve the DSVerKey of the recipient
	value, ok := userlib.KeystoreGet(DSVerKeyNameOfUser(senderUsername))
	if !ok {
		return &KeystoreGetError{fmt.Sprintf("cannot find %s's DSVerKey", senderUsername)}
	}
	// INFO: retrieve the shareInfo
	var sfo = new(ShareInfo)
	err = DatastoreAsyGet(userdata.DecKey, value, invitationPtr, sfo)
	if err != nil {
		return err
	}
	// INFO: key generations
	fileEncKey, encKeyErr := EncSymKeyGen(sfo.FileSymKey)
	if encKeyErr != nil {
		return encKeyErr
	}
	fileHmacKey, hmacKeyErr := HmacKeyGen(sfo.FileSymKey)
	if hmacKeyErr != nil {
		return hmacKeyErr
	}
	// INFO: retrieve the SubShareInfo
	var ssf = new(SubShareInfo)
	err = DatastoreSymGet(fileEncKey, fileHmacKey, sfo.SSInfo, ssf)
	if err != nil {
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
	// INFO: searching the FileList in case that the file have been maliciously deleted
	uuidFromUsername, uuidErr := getUuidFromUsername(userdata.Username, 16)
	if uuidErr != nil {
		return uuidErr
	}
	var fl = new(FileList)
	datastoreGetErr := DatastoreSymGet(userEncSymKey, userHmacKey, uuidFromUsername, fl)
	if datastoreGetErr != nil {
		return datastoreGetErr
	}
	_, ok = (*fl)[filename]
	if ok {
		// INFO: already in the file list
		return &DatastoreGetError{"this name already in the file list"}
	}
	// INFO: insert a new filename in the list
	(*fl)[filename] = true
	datastoreSetErr := DatastoreSymSet(userEncSymKey, userHmacKey, uuidFromUsername, fl)
	if datastoreSetErr != nil {
		return datastoreSetErr
	}
	// INFO: create a file in the namespace
	ufStKey, addGenErr := AddressOfUUIDFileGen(userdata.Username, filename)
	if addGenErr != nil {
		return addGenErr
	}
	// INFO: create a new file
	uf := &UUIDFile{UUID: ssf.UUIDBranch, SymKey: sfo.FileSymKey, CreatorHash: ssf.CreatorHash}
	err = DatastoreSymSet(userEncSymKey, userHmacKey, ufStKey, uf)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// INFO: check whether their is a file with such file name
	// INFO: check the current user with filename
	uid, err := AddressOfUUIDFileGen(userdata.Username, filename)
	// INFO: generate keys for users' encryption/decryption and hmac
	userEncSymKey, UserEncSymKeyErr := EncSymKeyGen(userdata.SymKey)
	if UserEncSymKeyErr != nil {
		return UserEncSymKeyErr
	}
	userHmacKey, UserHmacKeyErr := HmacKeyGen(userdata.SymKey)
	if UserHmacKeyErr != nil {
		return UserHmacKeyErr
	}
	// INFO: retrieve the file from the ds
	uf, aof, _, err := GetUUIDFile(uid, userEncSymKey, userHmacKey)
	if err != nil {
		return err
	}
	// INFO: key generations
	fileEncKey, encKeyErr := EncSymKeyGen(uf.SymKey)
	if encKeyErr != nil {
		return encKeyErr
	}
	fileHmacKey, hmacKeyErr := HmacKeyGen(uf.SymKey)
	if hmacKeyErr != nil {
		return hmacKeyErr
	}
	// INFO: check whether an invitation graph exists.
	id, err := UUIDOfInvitationGraph(userdata.Username, filename)
	if err != nil {
		return err
	}
	// INFO: check whether the file have been shared to rec
	var ig = new(InvitationGraph)
	err = DatastoreSymGet(userEncSymKey, userHmacKey, id, ig)
	if err != nil {
		return err
	}
	_, ok := (*ig)[recipientUsername]
	if !ok {
		return &DatastoreGetError{fmt.Sprintf("file not share to %s", recipientUsername)}
	}
	// INFO: remove the rec
	delete(*ig, recipientUsername)
	// INFO: change the uuid of file head
	newFhId := uuid.New()
	err = moveFileHead(fileEncKey, fileHmacKey, *aof, newFhId)
	// INFO: iterate the invitation graph, update the aof in the uuidBranch
	for key := range *ig {
		err = DatastoreSymSet(fileEncKey, fileHmacKey, (*ig)[key], newFhId)
		if err != nil {
			return err
		}
	}
	// INFO: write back the ig
	err = DatastoreSymSet(userEncSymKey, userHmacKey, id, ig)
	if err != nil {
		return err
	}
	// INFO: write back to the uf.UUID
	err = DatastoreSymSet(fileEncKey, fileHmacKey, uf.UUID, newFhId)
	if err != nil {
		return err
	}
	return nil
}
