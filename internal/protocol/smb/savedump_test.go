package smb

import (
	"errors"
	"strings"
	"testing"

	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeHiveFileClient struct {
	retrieveErrors map[string]error
	deleteErrors   map[string]error
	payload        []byte
	retrieved      []string
	deleted        []string
}

func (f *fakeHiveFileClient) RetrieveFile(shareName, filePath string, _ uint64, callback func([]byte) (int, error)) error {
	key := shareName + ":" + filePath
	f.retrieved = append(f.retrieved, key)
	if err := f.retrieveErrors[key]; err != nil {
		return err
	}
	_, err := callback(f.payload)
	return err
}

func (f *fakeHiveFileClient) DeleteFile(shareName, filePath string) error {
	key := shareName + ":" + filePath
	f.deleted = append(f.deleted, key)
	return f.deleteErrors[key]
}

func testHiveShares() []hiveSharePath {
	return []hiveSharePath{
		{name: "C$", path: `Windows\Temp\hive.tmp`, authoritative: true},
		{name: "ADMIN$", path: `Temp\hive.tmp`},
	}
}

func TestDownloadHiveRetriesCleanupThroughAlternateShare(t *testing.T) {
	client := &fakeHiveFileClient{
		retrieveErrors: map[string]error{},
		deleteErrors: map[string]error{
			`C$:Windows\Temp\hive.tmp`: errors.New("access denied"),
		},
		payload: []byte("hive data"),
	}

	data, err := downloadHiveAndCleanup(client, testHiveShares(), "SAM", `C:\Windows\Temp\hive.tmp`)

	require.NoError(t, err)
	assert.Equal(t, []byte("hive data"), data)
	assert.Equal(t, []string{
		`C$:Windows\Temp\hive.tmp`,
		`ADMIN$:Temp\hive.tmp`,
	}, client.deleted)
}

func TestDownloadHiveReturnsDataWithCleanupError(t *testing.T) {
	client := &fakeHiveFileClient{
		retrieveErrors: map[string]error{},
		deleteErrors: map[string]error{
			`C$:Windows\Temp\hive.tmp`: errors.New("access denied"),
			`ADMIN$:Temp\hive.tmp`:     errors.New("sharing violation"),
		},
		payload: []byte("hive data"),
	}

	data, err := downloadHiveAndCleanup(client, testHiveShares(), "SYSTEM", `C:\Windows\Temp\hive.tmp`)

	assert.Equal(t, []byte("hive data"), data)
	var cleanupErr *hiveCleanupError
	require.ErrorAs(t, err, &cleanupErr)
	assert.Contains(t, err.Error(), "could not remove")
	assert.Contains(t, err.Error(), "C$:Windows\\Temp\\hive.tmp")
	assert.Contains(t, err.Error(), "ADMIN$:Temp\\hive.tmp")
}

func TestDownloadHiveRetainsEveryRetrievalError(t *testing.T) {
	client := &fakeHiveFileClient{
		retrieveErrors: map[string]error{
			`C$:Windows\Temp\hive.tmp`: errors.New("C$ unavailable"),
			`ADMIN$:Temp\hive.tmp`:     errors.New("ADMIN$ unavailable"),
		},
		deleteErrors: map[string]error{},
	}

	data, err := downloadHiveAndCleanup(client, testHiveShares(), "SECURITY", `C:\Windows\Temp\hive.tmp`)

	assert.Nil(t, data)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "C$ unavailable"))
	assert.True(t, strings.Contains(err.Error(), "ADMIN$ unavailable"))
	assert.Equal(t, []string{`C$:Windows\Temp\hive.tmp`}, client.deleted)
}

func TestCleanupTreatsMissingRemoteFileAsSuccess(t *testing.T) {
	notFound := &gosmb.NTStatusError{
		Op:     "DeleteFile",
		Status: gosmb.StatusObjectNameNotFound,
		Err:    gosmb.StatusMap[gosmb.StatusObjectNameNotFound],
	}
	client := &fakeHiveFileClient{
		deleteErrors: map[string]error{
			`C$:Windows\Temp\hive.tmp`: notFound,
		},
	}

	err := cleanupRemoteHive(client, testHiveShares(), 0)

	require.NoError(t, err)
	assert.Equal(t, []string{`C$:Windows\Temp\hive.tmp`}, client.deleted)
}

func TestCleanupDoesNotLetAlternateAbsenceHideCanonicalDeletionFailure(t *testing.T) {
	notFound := &gosmb.NTStatusError{
		Op:     "DeleteFile",
		Status: gosmb.StatusObjectNameNotFound,
		Err:    gosmb.StatusMap[gosmb.StatusObjectNameNotFound],
	}
	client := &fakeHiveFileClient{
		deleteErrors: map[string]error{
			`C$:Windows\Temp\hive.tmp`: errors.New("access denied"),
			`ADMIN$:Temp\hive.tmp`:     notFound,
		},
	}

	err := cleanupRemoteHive(client, testHiveShares(), 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	assert.Equal(t, []string{
		`C$:Windows\Temp\hive.tmp`,
		`ADMIN$:Temp\hive.tmp`,
	}, client.deleted)
}
