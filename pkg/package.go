package rpmdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

type PackageInfo struct {
	Epoch           int
	Name            string
	Version         string
	Release         string
	Arch            string
	SourceRpm       string
	Size            int
	License         string
	Vendor          string
	Modularitylabel string
	Summary         string
	PGP             string

	BaseNames  []string
	DirIndexes []int
	DirNames   []string
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/tagexts.c#L752
func getNEVRA(indexEntries []indexEntry) (*PackageInfo, error) {
	pkgInfo := &PackageInfo{}
	for _, ie := range indexEntries {
		switch ie.Info.Tag {
		case RPMTAG_DIRINDEXES:
			if ie.Info.Type != RPM_INT32_TYPE {
				return nil, xerrors.New("invalid tag dir indexes")
			}

			indexes, err := int32Array(ie)
			if err != nil {
				return nil, xerrors.Errorf("unable to read dir indexes: %w", err)
			}
			pkgInfo.DirIndexes = indexes
		case RPMTAG_DIRNAMES:
			if ie.Info.Type != RPM_STRING_ARRAY_TYPE {
				return nil, xerrors.New("invalid tag dir names")
			}

			dirNames, err := stringArray(ie)
			if err != nil {
				return nil, xerrors.Errorf("unable to read dir names: %w", err)
			}
			pkgInfo.DirNames = dirNames
		case RPMTAG_BASENAMES:
			if ie.Info.Type != RPM_STRING_ARRAY_TYPE {
				return nil, xerrors.New("invalid tag base names")
			}

			baseNames, err := stringArray(ie)
			if err != nil {
				return nil, xerrors.Errorf("unable to read dir names: %w", err)
			}
			pkgInfo.BaseNames = baseNames
		case RPMTAG_MODULARITYLABEL:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag modularitylabel")
			}
			pkgInfo.Modularitylabel = string(bytes.TrimRight(ie.Data, "\x00"))
		case RPMTAG_NAME:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag name")
			}
			pkgInfo.Name = string(bytes.TrimRight(ie.Data, "\x00"))
		case RPMTAG_EPOCH:
			if ie.Info.Type != RPM_INT32_TYPE {
				return nil, xerrors.New("invalid tag epoch")
			}

			var epoch int32
			reader := bytes.NewReader(ie.Data)
			if err := binary.Read(reader, binary.BigEndian, &epoch); err != nil {
				return nil, xerrors.Errorf("failed to read binary (epoch): %w", err)
			}
			pkgInfo.Epoch = int(epoch)
		case RPMTAG_VERSION:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag version")
			}
			pkgInfo.Version = string(bytes.TrimRight(ie.Data, "\x00"))
		case RPMTAG_RELEASE:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag release")
			}
			pkgInfo.Release = string(bytes.TrimRight(ie.Data, "\x00"))
		case RPMTAG_ARCH:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag arch")
			}
			pkgInfo.Arch = string(bytes.TrimRight(ie.Data, "\x00"))
		case RPMTAG_SOURCERPM:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag sourcerpm")
			}
			pkgInfo.SourceRpm = string(bytes.TrimRight(ie.Data, "\x00"))
			if pkgInfo.SourceRpm == "(none)" {
				pkgInfo.SourceRpm = ""
			}
		case RPMTAG_LICENSE:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag license")
			}
			pkgInfo.License = string(bytes.TrimRight(ie.Data, "\x00"))
			if pkgInfo.License == "(none)" {
				pkgInfo.License = ""
			}
		case RPMTAG_VENDOR:
			if ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag vendor")
			}
			pkgInfo.Vendor = string(bytes.TrimRight(ie.Data, "\x00"))
			if pkgInfo.Vendor == "(none)" {
				pkgInfo.Vendor = ""
			}
		case RPMTAG_SIZE:
			if ie.Info.Type != RPM_INT32_TYPE {
				return nil, xerrors.New("invalid tag size")
			}

			var size int32
			reader := bytes.NewReader(ie.Data)
			if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
				return nil, xerrors.Errorf("failed to read binary (size): %w", err)
			}
			pkgInfo.Size = int(size)
		case RPMTAG_SUMMARY:
			// some libraries have a string value instead of international string, so accounting for both
			if ie.Info.Type != RPM_I18NSTRING_TYPE && ie.Info.Type != RPM_STRING_TYPE {
				return nil, xerrors.New("invalid tag summary")
			}
			// since this is an international string, getting the first null terminated string
			pkgInfo.Summary = string(bytes.Split(ie.Data, []byte{0})[0])
		case RPMTAG_PGP:
			type pgpSig struct {
				_          [3]byte
				Date       int32
				KeyID      [8]byte
				PubKeyAlgo uint8
				HashAlgo   uint8
			}

			type textSig struct {
				_          [2]byte
				PubKeyAlgo uint8
				HashAlgo   uint8
				_          [4]byte
				Date       int32
				_          [4]byte
				KeyID      [8]byte
			}

			type pgp4Sig struct {
				_          [2]byte
				PubKeyAlgo uint8
				HashAlgo   uint8
				_          [17]byte
				KeyID      [8]byte
				_          [2]byte
				Date       int32
			}

			pubKeyLookup := map[uint8]string{
				0x01: "RSA",
			}
			hashLookup := map[uint8]string{
				0x02: "SHA1",
				0x08: "SHA256",
			}

			if ie.Info.Type != RPM_BIN_TYPE {
				return nil, xerrors.New("invalid PGP signature")
			}

			var tag, signatureType, version uint8
			r := bytes.NewReader(ie.Data)
			err := binary.Read(r, binary.BigEndian, &tag)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &signatureType)
			if err != nil {
				return nil, err
			}
			err = binary.Read(r, binary.BigEndian, &version)
			if err != nil {
				return nil, err
			}

			var pubKeyAlgo, hashAlgo, pkgDate string
			var keyId [8]byte

			switch signatureType {
			case 0x01:
				switch version {
				case 0x1c:
					sig := textSig{}
					err = binary.Read(r, binary.BigEndian, &sig)
					if err != nil {
						return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
					}
					pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
					hashAlgo = hashLookup[sig.HashAlgo]
					pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
					keyId = sig.KeyID
				default:
					sig := pgpSig{}
					err = binary.Read(r, binary.BigEndian, &sig)
					if err != nil {
						return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
					}
					pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
					hashAlgo = hashLookup[sig.HashAlgo]
					pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
					keyId = sig.KeyID
				}
			case 0x02:
				switch version {
				case 0x33:
					sig := pgp4Sig{}
					err = binary.Read(r, binary.BigEndian, &sig)
					if err != nil {
						return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
					}
					pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
					hashAlgo = hashLookup[sig.HashAlgo]
					pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
					keyId = sig.KeyID
				default:
					sig := pgpSig{}
					err = binary.Read(r, binary.BigEndian, &sig)
					if err != nil {
						return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
					}
					pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
					hashAlgo = hashLookup[sig.HashAlgo]
					pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
					keyId = sig.KeyID
				}
			}
			pkgInfo.PGP = fmt.Sprintf("%s/%s, %s, Key ID %x", pubKeyAlgo, hashAlgo, pkgDate, keyId)
		}
	}
	return pkgInfo, nil
}

func int32Array(ie indexEntry) ([]int, error) {
	var values []int
	reader := bytes.NewReader(ie.Data)
	for i := 0; i < int(ie.Info.Count); i++ {
		var value int32
		err := binary.Read(reader, binary.BigEndian, &value)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, xerrors.Errorf("failed to read int32: %w", err)
		}
		values = append(values, int(value))
	}

	return values, nil
}

func stringArray(ie indexEntry) ([]string, error) {
	var values []string
	var data []byte
	for _, b := range ie.Data {
		// NULL terminates the string.
		if b == 0 {
			values = append(values, string(data))
			data = []byte{}
			continue
		}
		data = append(data, b)
	}

	return values, nil
}

func (p *PackageInfo) InstalledFiles() ([]string, error) {
	if len(p.DirNames) == 0 || len(p.DirIndexes) == 0 || len(p.BaseNames) == 0 {
		return nil, nil
	}

	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/tagexts.c#L68-L70
	if len(p.DirIndexes) != len(p.BaseNames) || len(p.DirNames) > len(p.BaseNames) {
		return nil, xerrors.Errorf("invalid rpm %s", p.Name)
	}

	var filePaths []string
	for i, baseName := range p.BaseNames {
		dir := p.DirNames[p.DirIndexes[i]]
		filePaths = append(filePaths, filepath.Join(dir, baseName))
	}

	return filePaths, nil
}
