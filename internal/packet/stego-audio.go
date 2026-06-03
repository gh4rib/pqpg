package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-audio/aiff"
	"github.com/go-audio/audio"
	"github.com/go-audio/wav"
)

// decodeAudio intelligently routes the carrier to the correct decoder based on its extension.
func decodeAudio(carrierFile *os.File, ext string) (*audio.IntBuffer, error) {
	switch ext {
	case ".wav":
		decoder := wav.NewDecoder(carrierFile)
		if !decoder.IsValidFile() {
			return nil, errors.New("invalid WAV file")
		}
		return decoder.FullPCMBuffer()
	case ".aiff", ".aif":
		decoder := aiff.NewDecoder(carrierFile)
		if !decoder.IsValidFile() {
			return nil, errors.New("invalid AIFF file")
		}
		return decoder.FullPCMBuffer()
	default:
		return nil, fmt.Errorf("unsupported audio format: %s. Please use .wav or .aiff", ext)
	}
}

// EmbedInAudio hides a raw data stream inside the LSBs of a WAV or AIFF file, outputting to WAV/AIFF.
func EmbedInAudio(payload io.Reader, carrierPath, outputPath, outputFormat string) error {
	// 1. Read Payload and Calculate Size
	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return fmt.Errorf("failed to read payload: %w", err)
	}

	payloadLen := uint32(len(payloadBytes))
	if payloadLen == 0 {
		return errors.New("payload is empty")
	}

	bitStream := new(bytes.Buffer)
	lengthHeader := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthHeader, payloadLen)
	bitStream.Write(lengthHeader)
	bitStream.Write(payloadBytes)

	data := bitStream.Bytes()
	totalBits := len(data) * 8

	// 2. Load the Carrier Track
	carrierFile, err := os.Open(carrierPath)
	if err != nil {
		return fmt.Errorf("failed to open carrier audio: %w", err)
	}
	defer carrierFile.Close()

	ext := strings.ToLower(filepath.Ext(carrierPath))
	buf, err := decodeAudio(carrierFile, ext)
	if err != nil {
		return fmt.Errorf("failed to decode PCM buffer: %w", err)
	}

	// 3. Capacity Check (1 bit per audio sample)
	if totalBits > len(buf.Data) {
		return fmt.Errorf("payload too large. Need %d samples, track only has %d samples", totalBits, len(buf.Data))
	}

	// 4. High-Speed Acoustic LSB Injection
	var bitIndex int
	for i := 0; i < len(buf.Data) && bitIndex < totalBits; i++ {
		byteIdx := bitIndex / 8
		bitInByte := 7 - (bitIndex % 8)
		bit := int((data[byteIdx] >> bitInByte) & 1)

		// Zero out the lowest bit of the acoustic sample, then inject our bit
		buf.Data[i] = (buf.Data[i] &^ 1) | bit
		bitIndex++
	}

	// 5. Save as pristine, uncompressed WAV or AIFF
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create stego audio file: %w", err)
	}
	defer outFile.Close()

	outExt := strings.ToLower(outputFormat)
	if outExt == "aiff" {
		encoder := aiff.NewEncoder(outFile, buf.Format.SampleRate, buf.SourceBitDepth, buf.Format.NumChannels)
		if err := encoder.Write(buf); err != nil {
			return fmt.Errorf("failed to encode AIFF: %w", err)
		}
		if err := encoder.Close(); err != nil {
			return err
		}
	} else {
		// Default to WAV
		encoder := wav.NewEncoder(outFile, buf.Format.SampleRate, buf.SourceBitDepth, buf.Format.NumChannels, 1)
		if err := encoder.Write(buf); err != nil {
			return fmt.Errorf("failed to encode WAV: %w", err)
		}
		if err := encoder.Close(); err != nil {
			return err
		}
	}

	return nil
}

// ExtractFromAudio pulls an LSB-hidden payload out of a WAV or AIFF carrier track.
func ExtractFromAudio(carrierPath string, output io.Writer) error {
	carrierFile, err := os.Open(carrierPath)
	if err != nil {
		return fmt.Errorf("failed to open stego audio: %w", err)
	}
	defer carrierFile.Close()

	ext := strings.ToLower(filepath.Ext(carrierPath))
	buf, err := decodeAudio(carrierFile, ext)
	if err != nil {
		return fmt.Errorf("failed to decode PCM buffer: %w", err)
	}

	var extractedData []byte
	var currentByte byte
	var bitIndex int
	var payloadLen uint32
	var lengthFound bool

	// High-Speed Acoustic LSB Extraction
	for i := 0; i < len(buf.Data); i++ {
		bit := byte(buf.Data[i] & 1)
		currentByte = (currentByte << 1) | bit
		bitIndex++

		if bitIndex%8 == 0 {
			extractedData = append(extractedData, currentByte)
			currentByte = 0

			if !lengthFound && len(extractedData) == 4 {
				payloadLen = binary.LittleEndian.Uint32(extractedData)
				lengthFound = true
				extractedData = nil

				maxPossibleBytes := uint32(len(buf.Data) / 8)
				if payloadLen > maxPossibleBytes || payloadLen == 0 {
					return errors.New("CRITICAL: Stated payload length exceeds audio capacity. Carrier is corrupt or empty")
				}
			}

			if lengthFound && uint32(len(extractedData)) == payloadLen {
				_, err := output.Write(extractedData)
				return err
			}
		}
	}

	return errors.New("failed to find a complete payload inside the carrier track")
}