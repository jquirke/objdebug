package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"cmd/internal/archive"
	"cmd/internal/goobj"
	"cmd/internal/objabi"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: go tool objdebug binary\n\n")
	flag.PrintDefaults()
	os.Exit(2)
}

var (
	flagBool = flag.Bool("relocs", false, "Print relocation info")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("objdump: ")

	flag.Usage = usage

	flag.Parse()

	if flag.NArg() != 1 {
		usage()
	}

	fileName := flag.Arg(0)
	if err := dumparcfiledebug(fileName); err != nil {
		log.Fatalf("error dumping %s: %v", fileName, err)
	}
}

func dumparcfiledebug(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	// handles naked goobj correctly as well
	a, err := archive.Parse(f, true)
	if err != nil {
		return fmt.Errorf("archive parse: %w", err)
	}

	for i, entry := range a.Entries {
		if entry.Obj == nil {
			continue
		}
		th := strings.TrimRight(strings.Replace(string(entry.Obj.TextHeader), "\n!\n", "", -1), "\n")
		off, sz := entry.Obj.Offset, entry.Obj.Size
		fmt.Printf("****Object %d\nTextHeader  %s\nOffset %d\nSize %d\n", i,
			th, off, sz)

		bytes := make([]byte, sz)
		n, err := f.ReadAt(bytes, off)
		if err != nil {
			return fmt.Errorf("could not read file %w", err)
		}
		if int64(n) != sz {
			return fmt.Errorf("truncated read: want %d got %d bytes", sz, n)
		}
		r := goobj.NewReaderFromBytes(bytes, false)
		if r == nil {
			return errors.New("file is not a valid go object file")
		}
		dumpobjfiledebug(r)
		fmt.Printf("\n")
	}

	return nil
}

func dumpobjfiledebug(r *goobj.Reader) {
	fmt.Printf("FingerPrint %s\nFlags %08X (%s)\n",
		fingerprint(r.Fingerprint()), r.Flags(), objfileheaderflags(r.Flags()))

	dumpobjfilesizesummary(r)
	dumpautolibs(r)
	dumppkglist(r)
	dumpfilelist(r)
	dumpsyms(r)
	dumprefflags(r)
}

func fingerprint(fp goobj.FingerprintType) string {
	return hex.EncodeToString(fp[:])
}

func objfileheaderflags(flags uint32) string {
	flagNames := []string{}
	for _, f := range []struct {
		bits uint32
		name string
	}{
		{goobj.ObjFlagShared, "Shared"},
		{goobj.ObjFlagFromAssembly, "FromAssembly"},
		{goobj.ObjFlagUnlinkable, "Unlinkable"},
	} {
		if flags&f.bits != 0 {
			flagNames = append(flagNames, f.name)
		}
	}
	return strings.Join(flagNames, ", ")
}

func dumpobjfilesizesummary(r *goobj.Reader) {
	fmt.Printf("NAutoLib: %d\n", len(r.Autolib()))
	fmt.Printf("NPkg: %d\n", r.NPkg())
	fmt.Printf("NFile: %d\n", r.NFile())
	fmt.Printf("NSym: %d\n", r.NSym())
	fmt.Printf("NHashed64Defs: %d\n", r.NHashed64def())
	fmt.Printf("NHashedDefs: %d\n", r.NHasheddef())
	fmt.Printf("NonPkgDefs: %d\n", r.NNonpkgdef())
	fmt.Printf("NonPkgRefs: %d\n", r.NNonpkgref())
	fmt.Printf("NRefFlags: %d\n", r.NRefFlags())
}

func dumpautolibs(r *goobj.Reader) {
	autolibs := r.Autolib()
	for i, autolib := range autolibs {
		fmt.Printf("   Autolib %3d: %-20s %s\n", i, autolib.Pkg, fingerprint(autolib.Fingerprint))
	}
}

func dumppkglist(r *goobj.Reader) {
	pkgs := r.Pkglist()
	for i, pkg := range pkgs {
		if i == 0 { //PkgIdxInvalid
			continue
		}
		fmt.Printf("   Pkg %3d: %s\n", i, pkg)
	}
}

func dumpfilelist(r *goobj.Reader) {
	nfiles := r.NFile()
	for i := 0; i < nfiles; i++ {
		fmt.Printf("   File %3d: %s\n", i, r.File(i))
	}
}

func dumpsyms(r *goobj.Reader) {
	symclasses := []struct {
		syms int
		name string
	}{
		{r.NSym(), "Sym"},
		{r.NHashed64def(), "Hashed64Def"},
		{r.NHasheddef(), "HashedDef"},
		{r.NNonpkgdef(), "NonPkgDef"},
		{r.NNonpkgref(), "NonPkgRef"},
	}
	totalSym := 0
	for _, cls := range symclasses {
		for i := 0; i < cls.syms; i++ {
			dumpsym(cls.name, i, r.Sym(uint32(totalSym+i)), r)
		}
		totalSym += cls.syms
	}
}
func dumpsym(cls string, i int, sym *goobj.Sym, r *goobj.Reader) {
	fmt.Printf("   %-11s %4d: ABI:%04X Type:%12s Size:%8d Flag1[%24s] Flag2[%16s], Relocs=%4d [%s]\n", cls, i,
		int(sym.ABI()), symtype(sym.Type()), int(sym.Siz()), symflag(sym.Flag()), symflag2(sym.Flag2()), r.NReloc(uint32(i)), sym.Name(r))
	if *flagBool {
		for i, reloc := range r.Relocs(uint32(i)) {
			fmt.Printf("      R%3d: Off: %08X Siz: %02X Sym (%8s, %d) Address: %08X\n", i,
				int(reloc.Off()), int(reloc.Siz()),
				pkgidx(reloc.Sym().PkgIdx), int(reloc.Sym().SymIdx), int(reloc.Add()))
		}
	}
}

func symtype(t uint8) string {
	symTypes := map[objabi.SymKind]string{
		objabi.Sxxx: "Sxxx",
		// Executable instructions
		objabi.STEXT: "STEXT",
		// Read only static data
		objabi.SRODATA: "SRODATA",
		// Static data that does not contain any pointers
		objabi.SNOPTRDATA: "SNOPTRDATA",
		// Static data
		objabi.SDATA: "SDATA",
		// Statically data that is initially all 0s
		objabi.SBSS: "SBSS",
		// Statically data that is initially all 0s and does not contain pointers
		objabi.SNOPTRBSS: "SNOPTRBSS",
		// Thread-local data that is initially all 0s
		objabi.STLSBSS: "STLSBSS",
		// Debugging data
		objabi.SDWARFCUINFO: "SDWARFCUINFO",
		objabi.SDWARFCONST:  "SDWARFCONST",
		objabi.SDWARFFCN:    "SDWARFFCN",
		objabi.SDWARFABSFCN: "SDWARFABSFCN",
		objabi.SDWARFTYPE:   "SDWARFTYPE",
		objabi.SDWARFVAR:    "SDWARFVAR",
		objabi.SDWARFRANGE:  "SDWARFRANGE",
		objabi.SDWARFLOC:    "SDWARFLOC",
		objabi.SDWARFLINES:  "SDWARFLINES",
		// Coverage instrumentation counter for libfuzzer.
		objabi.SLIBFUZZER_8BIT_COUNTER: "SLIBFUZZER_8BIT_COUNTER",
		// Coverage instrumentation counter, aux variable for cmd/cover
		objabi.SCOVERAGE_COUNTER: "SCOVERAGE_COUNTER",
		objabi.SCOVERAGE_AUXVAR:  "SCOVERAGE_AUXVAR",

		objabi.SSEHUNWINDINFO: "SSEHUNWINDINFO",
	}
	return symTypes[objabi.SymKind(t)]
}

// aka "symattr"
func symflag(flags uint8) string {
	flagNames := []string{}
	for _, f := range []struct {
		bits uint8
		name string
	}{
		{goobj.SymFlagDupok, "Dupok"},
		{goobj.SymFlagLocal, "Local"},
		{goobj.SymFlagTypelink, "Typelink"},
		{goobj.SymFlagLeaf, "Leaf"},
		{goobj.SymFlagNoSplit, "NoSplit"},
		{goobj.SymFlagReflectMethod, "ReflectMethod"},
		{goobj.SymFlagGoType, "GoType"},
	} {
		if flags&f.bits != 0 {
			flagNames = append(flagNames, f.name)
		}
	}
	return strings.Join(flagNames, ", ")
}

func symflag2(flags uint8) string {
	flagNames := []string{}
	for _, f := range []struct {
		bits uint8
		name string
	}{
		{goobj.SymFlagUsedInIface, "UsedInIface"},
		{goobj.SymFlagItab, "Itab"},
		{goobj.SymFlagDict, "Dict"},
		{goobj.SymFlagPkgInit, "PkgInit"},
	} {
		if flags&f.bits != 0 {
			flagNames = append(flagNames, f.name)
		}
	}
	return strings.Join(flagNames, ", ")
}

func pkgidx(idx uint32) string {
	switch idx {
	case (1 << 31) - 1:
		return "None"
	case (1 << 31) - 2:
		return "Hashed64"
	case (1 << 31) - 3:
		return "Hashed"
	case (1 << 31) - 4:
		return "Builtin"
	case (1 << 31) - 5:
		return "Self"
	case 0:
		return "Invalid"
	default:
		return strconv.Itoa(int(idx))
	}
}

// this is only used as of Nov 2023 to indicate that an externally referenced symbol
// has used in iface attr set.
func dumprefflags(r *goobj.Reader) {
	nrefflags := r.NRefFlags()
	for i := 0; i < nrefflags; i++ {
		refflag := r.RefFlags(i)
		fmt.Printf("nrefflag: %4d: SymRef<%4d, %d> flag %02X flag2 %02X\n", i,
			refflag.Sym().PkgIdx, refflag.Sym().SymIdx, refflag.Flag(), refflag.Flag2())
	}
}
