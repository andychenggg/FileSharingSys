package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	"encoding/json"
	_ "errors"
	"fmt"
	"github.com/google/uuid"
	"strconv"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

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

func UUIDOfInvitationGraph(username string, filename string) (id uuid.UUID, err error) {
	return uuid.FromBytes(
		userlib.Hash(
			append(
				userlib.Hash([]byte(username)), userlib.Hash([]byte(filename))...,
			),
		)[16:32],
	)
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	//var doris *client.User
	//var eve *client.User
	//var frank *client.User
	//var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	const dorisFile = "dorisFile.txt"
	const eveFile = "eveFile.txt"
	const frankFile = "frankFile.txt"
	const graceFile = "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("User Authentication Tests", func() {
		Specify("UAT: InitUser with existed Username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("err: %s", err)
		})

		Specify("UAT: InitUser with empty Username", func() {
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("err: %s", err)
		})

		Specify("UAT: GetUser with invalid Username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			alice, err = client.GetUser("alice1", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("err: %s", err)
		})

		Specify("UAT: GetUser with invalid password", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			alice, err = client.GetUser("alice", defaultPassword+"wrong")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("err: %s", err)
		})

		Specify("UAT: malicious actions", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)

			// INFO: delete the user
			id, _ := uuid.FromBytes(userlib.Hash([]byte("alice"))[0 : 0+16])
			userlib.DatastoreDelete(id)
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("err: %s", err)

			// INFO: flip some bits
			id, _ = uuid.FromBytes(userlib.Hash([]byte("bob"))[0 : 0+16])
			value, ok := userlib.DatastoreGet(id)
			if ok {
				value[(len(value))/2] = 255 - value[(len(value))/2]
				userlib.DatastoreSet(id, value)
				alice, err = client.GetUser("alice", defaultPassword)
				Expect(err).ToNot(BeNil())
				userlib.DebugMsg("err: %s", err)
			}
		})

		Specify("UAT: username and password requirements", func() {
			// INFO: empty password
			userlib.DebugMsg("INFO: empty password")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			// INFO: case-sensitive
			userlib.DebugMsg("INFO: case-sensitive")
			alice, err = client.GetUser("Alice", defaultPassword)
			Expect(err).NotTo(BeNil())
			userlib.DebugMsg("err: %s", err)

			// INFO: non-alphanumeric
			userlib.DebugMsg("INFO: non-alphanumeric")
			bob, err = client.InitUser("\xff", "\xfe")
			Expect(err).To(BeNil())

			// INFO: same password
			userlib.DebugMsg("INFO: same password")
			charles, err = client.InitUser("charles", "\xfe")
			Expect(err).To(BeNil())

		})
	})

	Describe("File Operation Tests", func() {
		Specify("FOT: store/load file", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			// INFO: another device
			aliceNew, _ := client.GetUser("alice", defaultPassword)

			// INFO: store a file and loaded by another device
			userlib.DebugMsg("INFO: store a file and loaded by another device")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data, err := aliceNew.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// INFO: overwrite a file and loaded by another device
			userlib.DebugMsg("INFO: overwrite a file and loaded by another device")
			err = aliceNew.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			// INFO: tamper the file
			userlib.DebugMsg("INFO: tamper the file")
			id, err := AddressOfUUIDFileGen("alice", aliceFile)
			Expect(err).To(BeNil())
			value, ok := userlib.DatastoreGet(id)
			if ok {
				value[len(value)/3] = 255 - value[len(value)/3]
				userlib.DatastoreSet(id, value)
				data, err = alice.LoadFile(aliceFile)
				Expect(err).NotTo(BeNil())
				fmt.Printf("err: %s\n", err)
			}

			// INFO: delete the file directly
			userlib.DebugMsg("INFO: delete the file directly")
			if ok {
				userlib.DatastoreDelete(id)
				data, err = alice.LoadFile(aliceFile)
				Expect(err).NotTo(BeNil())
				fmt.Printf("err: %s\n", err)
				err = aliceNew.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).NotTo(BeNil())
				fmt.Printf("err: %s\n", err)
			}

			// INFO: non-alphanumeric
			userlib.DebugMsg("INFO: non-alphanumeric")
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())
			data, err = aliceNew.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// INFO: load an non-existed file
			userlib.DebugMsg("INFO: load an non-existed file")
			data, err = alice.LoadFile("\xff")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

			// INFO: loaded by other user
			userlib.DebugMsg("loaded by other user")
			bob, err = client.InitUser("bob", defaultPassword)
			data, err = bob.LoadFile("")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
		})

		Specify("FOT: append to file", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			// INFO: another device
			aliceNew, _ := client.GetUser("alice", defaultPassword)

			// INFO: normal behavior
			userlib.DebugMsg("normal behavior")
			err = alice.StoreFile("", []byte(contentOne))
			err = aliceNew.AppendToFile("", []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			// INFO: append to a non-existed file
			userlib.DebugMsg("append to a non-existed file")
			err = alice.AppendToFile("\xff\n", []byte(contentOne))
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

			// INFO: malicious action
			userlib.DebugMsg("malicious action")
			id, err := AddressOfUUIDFileGen("alice", "")
			Expect(err).To(BeNil())
			value, ok := userlib.DatastoreGet(id)
			if ok {
				value[len(value)/3] = 255 - value[len(value)/3]
				userlib.DatastoreSet(id, value)
				err = alice.AppendToFile("", []byte(contentOne))
				Expect(err).NotTo(BeNil())
				fmt.Printf("err: %s\n", err)
			}
		})
	})

	Describe("Sharing and Revocation Test", func() {
		Specify("Share then read, store, append to, share", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)

			err = alice.StoreFile("\n", []byte(contentOne))
			Expect(err).To(BeNil())

			// INFO: share to bob
			userlib.DebugMsg("INFO: share to bob")
			ip, err := alice.CreateInvitation("\n", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ip, bobFile)
			Expect(err).To(BeNil())
			// INFO: share to bob
			userlib.DebugMsg("INFO: bob shares the file to charles")
			ip, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", ip, charlesFile)
			Expect(err).To(BeNil())

			// INFO: read, overwrite and append to
			userlib.DebugMsg("INFO: read, overwrite and append to")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = bob.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile("\n")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			err = alice.StoreFile("\n", []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			err = alice.AppendToFile("\n", []byte(contentThree))
			Expect(err).To(BeNil())
			err = bob.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile("\n")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree + contentOne + contentTwo)))
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree + contentOne + contentTwo)))
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree + contentOne + contentTwo)))

		})

		Specify("Create Invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)

			err = alice.StoreFile("\n", []byte(contentOne))
			Expect(err).To(BeNil())

			// INFO: non-exist file
			userlib.DebugMsg("INFO: non-exist file")
			_, err := alice.CreateInvitation("\t", "bob")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

			// INFO: non-exist user
			userlib.DebugMsg("INFO: non-exist user")
			_, err = alice.CreateInvitation("\n", "bob2")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
		})

		Specify("Accept Invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)

			err = alice.StoreFile("\n", []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = charles.StoreFile(charlesFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// INFO: choose a repeat filename
			userlib.DebugMsg("INFO: choose a repeat filename")
			ip, err := alice.CreateInvitation("\n", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ip, bobFile)
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

			// INFO: invalid ptr
			ip = uuid.New()
			err = bob.AcceptInvitation("alice", ip, "\n")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

			// INFO: ptr from another user
			ip, err = charles.CreateInvitation(charlesFile, "bob")
			err = bob.AcceptInvitation("alice", ip, "\n")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			err = bob.AcceptInvitation("charles", ip, "\n")
			Expect(err).To(BeNil())
		})

		Specify("Revocation Tests: ", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)
			_, err := client.InitUser("doris", defaultPassword)

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			// INFO: A invites B
			ip, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ip, bobFile)
			Expect(err).To(BeNil())
			// INFO: A invites C
			ip, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", ip, charlesFile)
			Expect(err).To(BeNil())
			// INFO: try to load
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			// INFO: A revokes B
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile(bobFile)
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			err = bob.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			// INFO: C can still access it
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			// INFO: revocation with wrong username
			err = alice.RevokeAccess(aliceFile, "charles1")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			err = alice.RevokeAccess(aliceFile, "doris")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

			// INFO: revocation with wrong filename
			err = alice.RevokeAccess(aliceFile+"1", "charles")
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)

		})

		/**
		A: [
			B: [
				D: [
					F
				],
				E
			],
			C: [
				G
			]
		]
		*/
		Specify("Complicate Invitation Graph: ", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)
			doris, err := client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			eve, err := client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())
			frank, err := client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())
			grace, err := client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			// INFO: A invites B, C
			ip, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ip, bobFile)
			Expect(err).To(BeNil())
			ip, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", ip, charlesFile)
			Expect(err).To(BeNil())
			// INFO: B invites D, E
			ip, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("bob", ip, dorisFile)
			Expect(err).To(BeNil())
			ip, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("bob", ip, eveFile)
			Expect(err).To(BeNil())
			// INFO: D invites F
			ip, err = doris.CreateInvitation(dorisFile, "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("doris", ip, frankFile)
			Expect(err).To(BeNil())
			// INFO: C invites G
			ip, err = charles.CreateInvitation(charlesFile, "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("charles", ip, graceFile)
			Expect(err).To(BeNil())

			// INFO: F load the file
			data, err := frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			// INFO: A changes the file, F loads it
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			// INFO: F append to it, G loads it
			err = frank.AppendToFile(frankFile, []byte(contentThree))
			Expect(err).To(BeNil())
			data, err = grace.LoadFile(graceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))
			// INFO: G overwrite it, B loads it
			err = grace.StoreFile(graceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			// INFO: B append to it, C loads it
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))
			// INFO: C appends to it, D loads it
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree + contentTwo)))
			// INFO: D overwrites it, A, E loads it
			err = doris.StoreFile(dorisFile, []byte(contentThree))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			// INFO: A revokes B, F try to append and load
			userlib.DebugMsg("INFO: A revokes B, F try to append and load")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			_, err = frank.LoadFile(frankFile)
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			err = frank.AppendToFile(frankFile, []byte(contentOne))
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			// INFO: G can still access it
			userlib.DebugMsg("INFO: G can still access it")
			err = grace.AppendToFile(graceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
			// INFO: E tries to load and append
			_, err = frank.LoadFile(frankFile)
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
			err = frank.AppendToFile(frankFile, []byte(contentOne))
			Expect(err).NotTo(BeNil())
			fmt.Printf("err: %s\n", err)
		})
	})

})
