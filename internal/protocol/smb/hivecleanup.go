package smb

import (
	"bytes"
	"errors"
	"fmt"

	gosmb "github.com/jfjallid/go-smb/smb"
)

type hiveFileClient interface {
	RetrieveFile(shareName, filePath string, offset uint64, callback func([]byte) (int, error)) error
	DeleteFile(shareName, filePath string) error
}

type hiveSharePath struct {
	name          string
	path          string
	authoritative bool
}

type hiveCleanupError struct {
	hiveName string
	tempPath string
	err      error
}

func (e *hiveCleanupError) Error() string {
	return fmt.Sprintf("downloaded %s hive but could not remove %s: %v", e.hiveName, e.tempPath, e.err)
}

func (e *hiveCleanupError) Unwrap() error {
	return e.err
}

func downloadHiveAndCleanup(session hiveFileClient, shares []hiveSharePath, hiveName, tempPath string) ([]byte, error) {
	var downloadErrors []error

	for index, share := range shares {
		var buf bytes.Buffer
		downloadErr := session.RetrieveFile(share.name, share.path, 0, func(data []byte) (int, error) {
			return buf.Write(data)
		})
		if downloadErr == nil {
			hiveData := buf.Bytes()
			if cleanupErr := cleanupRemoteHive(session, shares, index); cleanupErr != nil {
				return hiveData, &hiveCleanupError{
					hiveName: hiveName,
					tempPath: tempPath,
					err:      cleanupErr,
				}
			}
			return hiveData, nil
		}
		downloadErrors = append(downloadErrors, fmt.Errorf("retrieve %s:%s: %w", share.name, share.path, downloadErr))
	}

	cleanupErr := cleanupRemoteHive(session, shares, -1)
	if cleanupErr != nil {
		downloadErrors = append(downloadErrors, &hiveCleanupError{
			hiveName: hiveName,
			tempPath: tempPath,
			err:      cleanupErr,
		})
	}
	return nil, fmt.Errorf("failed to download %s hive: %w", hiveName, errors.Join(downloadErrors...))
}

func cleanupRemoteHive(session hiveFileClient, shares []hiveSharePath, preferred int) error {
	order := make([]int, 0, len(shares))
	if preferred >= 0 && preferred < len(shares) {
		order = append(order, preferred)
	}
	for index := range shares {
		if index != preferred {
			order = append(order, index)
		}
	}

	var cleanupErrors []error
	for _, index := range order {
		share := shares[index]
		err := session.DeleteFile(share.name, share.path)
		if err == nil {
			return nil
		}
		// The hive is saved to C:\Windows\Temp. Absence through C$ proves that
		// exact path is gone. ADMIN$ can map to a different Windows directory,
		// so absence there must not hide a failed deletion through C$.
		if isRemoteFileAbsent(err) {
			if share.authoritative {
				return nil
			}
			continue
		}
		cleanupErrors = append(cleanupErrors, fmt.Errorf("delete %s:%s: %w", share.name, share.path, err))
	}
	return errors.Join(cleanupErrors...)
}

func isRemoteFileAbsent(err error) bool {
	return errors.Is(err, gosmb.StatusMap[gosmb.StatusNoSuchFile]) ||
		errors.Is(err, gosmb.StatusMap[gosmb.StatusObjectNameNotFound]) ||
		errors.Is(err, gosmb.StatusMap[gosmb.StatusObjectPathNotFound])
}
