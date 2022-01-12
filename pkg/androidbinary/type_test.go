package androidbinary

import (
	"encoding/xml"
	"os"
	"testing"
)

func TestBool(t *testing.T) {
	type myMetaData struct {
		Name  string `xml:"http://schemas.android.com/apk/res/android name,attr"`
		Value Bool   `xml:"http://schemas.android.com/apk/res/android value,attr"`
	}
	type myXMLApplication struct {
		XMLName  xml.Name     `xml:"application"`
		MetaData []myMetaData `xml:"meta-data"`
	}
	type myXMLManifest struct {
		XMLName     xml.Name         `xml:"manifest"`
		Application myXMLApplication `xml:"application"`
	}

	f, err := os.Open("testdata/MyApplication/AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	xmlFile, err := NewXMLFile(f)
	if err != nil {
		t.Fatal(err)
	}

	arscFile, err := os.Open("testdata/MyApplication/resources.arsc")
	if err != nil {
		t.Fatal(err)
	}
	arsc, err := NewTableFile(arscFile)
	if err != nil {
		t.Fatal(err)
	}

	xmlManifest := new(myXMLManifest)
	err = xmlFile.Decode(xmlManifest, arsc, nil)
	if err != nil {
		t.Errorf("got %v want no error", err)
	}

	for _, data := range xmlManifest.Application.MetaData {
		switch data.Name {
		case "bool_test_true":
			v, err := data.Value.Bool()
			if err != nil {
				t.Error(err)
			}
			if !v {
				t.Errorf("unexpected value: %v", v)
			}
		case "bool_test_false":
			v, err := data.Value.Bool()
			if err != nil {
				t.Error(err)
			}
			if v {
				t.Errorf("unexpected value: %v", v)
			}
		case "bool_test_true_arsc":
			v, err := data.Value.Bool()
			if err != nil {
				t.Error(err)
			}
			if !v {
				t.Errorf("unexpected value: %v", v)
			}
		case "bool_test_false_arsc":
			v, err := data.Value.Bool()
			if err != nil {
				t.Error(err)
			}
			if v {
				t.Errorf("unexpected value: %v", v)
			}
		}
	}
}

func TestInt32(t *testing.T) {
	type myMetaData struct {
		Name  string `xml:"http://schemas.android.com/apk/res/android name,attr"`
		Value Int32  `xml:"http://schemas.android.com/apk/res/android value,attr"`
	}
	type myXMLApplication struct {
		XMLName  xml.Name     `xml:"application"`
		MetaData []myMetaData `xml:"meta-data"`
	}
	type myXMLManifest struct {
		XMLName     xml.Name         `xml:"manifest"`
		Application myXMLApplication `xml:"application"`
	}

	f, err := os.Open("testdata/MyApplication/AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	xmlFile, err := NewXMLFile(f)
	if err != nil {
		t.Fatal(err)
	}

	arscFile, err := os.Open("testdata/MyApplication/resources.arsc")
	if err != nil {
		t.Fatal(err)
	}
	arsc, err := NewTableFile(arscFile)
	if err != nil {
		t.Fatal(err)
	}

	xmlManifest := new(myXMLManifest)
	err = xmlFile.Decode(xmlManifest, arsc, nil)
	if err != nil {
		t.Errorf("got %v want no error", err)
	}

	for _, data := range xmlManifest.Application.MetaData {
		switch data.Name {
		case "int_test":
			v, err := data.Value.Int32()
			if err != nil {
				t.Error(err)
			}
			if v != 42 {
				t.Errorf("unexpected value: %v", v)
			}
		case "int_test_arsc":
			v, err := data.Value.Int32()
			if err != nil {
				t.Error(err)
			}
			if v != -42 {
				t.Errorf("unexpected value: %v", v)
			}
		}
	}
}

func TestString(t *testing.T) {
	type myMetaData struct {
		Name  string `xml:"http://schemas.android.com/apk/res/android name,attr"`
		Value String `xml:"http://schemas.android.com/apk/res/android value,attr"`
	}
	type myXMLApplication struct {
		XMLName  xml.Name     `xml:"application"`
		MetaData []myMetaData `xml:"meta-data"`
	}
	type myXMLManifest struct {
		XMLName     xml.Name         `xml:"manifest"`
		Application myXMLApplication `xml:"application"`
	}

	f, err := os.Open("testdata/MyApplication/AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	xmlFile, err := NewXMLFile(f)
	if err != nil {
		t.Fatal(err)
	}

	arscFile, err := os.Open("testdata/MyApplication/resources.arsc")
	if err != nil {
		t.Fatal(err)
	}
	arsc, err := NewTableFile(arscFile)
	if err != nil {
		t.Fatal(err)
	}

	xmlManifest := new(myXMLManifest)
	err = xmlFile.Decode(xmlManifest, arsc, nil)
	if err != nil {
		t.Errorf("got %v want no error", err)
	}

	for _, data := range xmlManifest.Application.MetaData {
		switch data.Name {
		case "string_test":
			v, err := data.Value.String()
			if err != nil {
				t.Error(err)
			}
			if v != "hogefuga" {
				t.Errorf("unexpected value: %v", v)
			}
		case "string_test_arsc":
			v, err := data.Value.String()
			if err != nil {
				t.Error(err)
			}
			if v != "foobar" {
				t.Errorf("unexpected value: %v", v)
			}
		}
	}
}
