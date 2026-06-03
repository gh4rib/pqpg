package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"  // Register GIF decoder
	_ "image/jpeg" // Register JPEG decoder
	"image/png"
	"io"
	"os"
	"strings"

	"golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff" // Register TIFF decoder
	_ "golang.org/x/image/webp" // Register WEBP decoder
)

// EmbedInImage hides a raw data stream inside the LSBs of ANY carrier image, outputting as PNG or BMP.
func EmbedInImage(payload io.Reader, carrierPath, outputPath, outputFormat string) error {
	// 1. Read Payload and Calculate Size
	payloadBytes, err := io.ReadAll(payload)
	if err != nil { return fmt.Errorf("failed to read payload: %w", err) }

	payloadLen := uint32(len(payloadBytes))
	if payloadLen == 0 { return errors.New("payload is empty") }

	// 2. Construct the bit stream: [4-Byte Length Header] + [Payload]
	bitStream := new(bytes.Buffer)
	lengthHeader := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthHeader, payloadLen)
	bitStream.Write(lengthHeader)
	bitStream.Write(payloadBytes)

	data := bitStream.Bytes()
	totalBits := len(data) * 8

	// 3. Load Carrier Image (Auto-detects JPG, PNG, BMP, GIF, TIFF, WEBP)
	carrierFile, err := os.Open(carrierPath)
	if err != nil { return fmt.Errorf("failed to open carrier image: %w", err) }
	defer carrierFile.Close()

	img, _, err := image.Decode(carrierFile)
	if err != nil { return fmt.Errorf("unsupported image format or corrupt file: %w", err) }

	bounds := img.Bounds()
	
	// Convert to high-performance NRGBA matrix for direct memory manipulation
	canvas := image.NewNRGBA(bounds)
	draw.Draw(canvas, bounds, img, bounds.Min, draw.Src)

	// 4. Capacity Check (3 bits per pixel: R, G, B)
	maxBits := (bounds.Dx() * bounds.Dy()) * 3
	if totalBits > maxBits {
		return fmt.Errorf("payload too large. Need %d bits, carrier only holds %d bits", totalBits, maxBits)
	}

	// 5. High-Speed LSB Injection
	var bitIndex int
	for i := 0; i < len(canvas.Pix) && bitIndex < totalBits; i += 4 {
		for j := 0; j < 3 && bitIndex < totalBits; j++ {
			byteIdx := bitIndex / 8
			bitInByte := 7 - (bitIndex % 8)
			bit := (data[byteIdx] >> bitInByte) & 1

			canvas.Pix[i+j] = (canvas.Pix[i+j] & 0xFE) | bit
			bitIndex++
		}
	}

	// 6. Save as Lossless Output (PNG or BMP)
	outFile, err := os.Create(outputPath)
	if err != nil { return fmt.Errorf("failed to create stego image: %w", err) }
	defer outFile.Close()

	format := strings.ToLower(outputFormat)
	if format == "bmp" {
		// BMP is completely uncompressed. Massive file size, but instant encoding.
		if err := bmp.Encode(outFile, canvas); err != nil {
			return fmt.Errorf("failed to encode BMP: %w", err)
		}
	} else {
		// Default to PNG. Smaller file size, slightly slower encoding due to DEFLATE math.
		encoder := png.Encoder{CompressionLevel: png.BestCompression}
		if err := encoder.Encode(outFile, canvas); err != nil {
			return fmt.Errorf("failed to encode PNG: %w", err)
		}
	}

	return nil
}

// ExtractFromImage pulls an LSB-hidden payload out of a PNG or BMP carrier.
func ExtractFromImage(carrierPath string, output io.Writer) error {
	carrierFile, err := os.Open(carrierPath)
	if err != nil { return fmt.Errorf("failed to open stego image: %w", err) }
	defer carrierFile.Close()

	// image.Decode will automatically figure out if the stego file is a PNG or a BMP
	img, _, err := image.Decode(carrierFile)
	if err != nil { return fmt.Errorf("unsupported image format: %w", err) }

	bounds := img.Bounds()
	canvas := image.NewNRGBA(bounds)
	draw.Draw(canvas, bounds, img, bounds.Min, draw.Src)

	var extractedData []byte
	var currentByte byte
	var bitIndex int
	var payloadLen uint32
	var lengthFound bool

	// High-Speed LSB Extraction
	for i := 0; i < len(canvas.Pix); i += 4 {
		for j := 0; j < 3; j++ {
			bit := canvas.Pix[i+j] & 1
			currentByte = (currentByte << 1) | bit
			bitIndex++

			if bitIndex%8 == 0 {
				extractedData = append(extractedData, currentByte)
				currentByte = 0

				if !lengthFound && len(extractedData) == 4 {
					payloadLen = binary.LittleEndian.Uint32(extractedData)
					lengthFound = true
					extractedData = nil 
					
					maxPossibleBytes := ((bounds.Dx() * bounds.Dy()) * 3) / 8
					if payloadLen > uint32(maxPossibleBytes) || payloadLen == 0 {
						return errors.New("CRITICAL: Stated payload length exceeds image capacity. Carrier is corrupt or empty")
					}
				}

				if lengthFound && uint32(len(extractedData)) == payloadLen {
					_, err := output.Write(extractedData)
					return err
				}
			}
		}
	}

	return errors.New("failed to find a complete payload inside the carrier image")
}