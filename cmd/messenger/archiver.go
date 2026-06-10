package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// resolveInputPath asks for a path. If it's a directory, it bundles it into a tar.gz.
// It returns the final absolute/relative path of the file to be processed.
func resolveInputPath(reader *bufio.Reader, promptMsg string) (string, error) {
	fmt.Print(promptMsg)
	inputPath := readInput(reader)

	info, err := os.Stat(inputPath)
	if err != nil {
		return "", fmt.Errorf("failed to access path: %w", err)
	}

	if !info.IsDir() {
		return inputPath, nil // Normal file, return exactly as entered
	}

	fmt.Printf("\n[*] '%s' is a Directory.\n", inputPath)
	fmt.Print("[?] Do you want PQPG to automatically bundle it into a compressed archive (.tar.gz)? (y/N): ")
	choice := readInput(reader)
	if strings.ToLower(choice) != "y" {
		return "", fmt.Errorf("operation aborted: directories cannot be encrypted natively without archiving")
	}

	outPath := filepath.Clean(inputPath) + ".tar.gz"
	fmt.Printf("[*] Bundling directory into %s (Maximum GZIP Compression). Please wait...\n", outPath)

	err = createTarball(inputPath, outPath)
	if err != nil {
		return "", fmt.Errorf("archiving failed: %w", err)
	}

	fmt.Println("[+] Archive created successfully.")
	return outPath, nil
}

// createTarball builds a standard .tar.gz file using maximum compression.
func createTarball(sourceDir, targetFilePath string) error {
	outFile, err := os.Create(targetFilePath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Use highest compression to save disk space before Post-Quantum encryption expands it
	gw, err := gzip.NewWriterLevel(outFile, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	sourceBase := filepath.Base(sourceDir)

	return filepath.Walk(sourceDir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}

		// Calculate relative paths so the unarchived folder structure remains intact
		relPath, err := filepath.Rel(sourceDir, file)
		if err != nil {
			return err
		}
		if relPath == "." {
			header.Name = sourceBase
		} else {
			header.Name = filepath.Join(sourceBase, relPath)
		}
		// Ensure cross-platform compatibility (Windows uses \, Tar requires /)
		header.Name = filepath.ToSlash(header.Name)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !fi.IsDir() {
			f, err := os.Open(file)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		return nil
	})
}
