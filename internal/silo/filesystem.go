package silo

import (
	"errors"
	"os"
	"syscall"
)

// CopyOrLinkFile attempts to create a hard link from srcPath to destPath.
// If that fails, it falls back to copying the file contents.
func CopyOrLinkFile(srcPath string, destPath string) error {

	// Attempt to create a hard link from src to dest. If that fails, fall back
	// to copying the file contents.
	if err := os.Link(srcPath, destPath); err == nil {
		return nil
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = destFile.ReadFrom(srcFile)
	return err
}

func MoveFile(srcPath string, destPath string) error {
	if err := os.Rename(srcPath, destPath); err != nil {

		// If the source file lives on a different filesystem, fall back to
		// copying its contents into place instead of renaming.
		var linkErr *os.LinkError
		if errors.As(err, &linkErr); linkErr.Err == syscall.EXDEV {
			if copyErr := CopyOrLinkFile(srcPath, destPath); copyErr != nil {
				return copyErr
			}

			// Best-effort cleanup of the source file; ignore ENOENT in case
			// it was moved or removed it.
			if rmErr := os.Remove(srcPath); rmErr != nil && !os.IsNotExist(rmErr) {
				return rmErr
			}
			return nil
		}
		return err
	}

	return nil
}
