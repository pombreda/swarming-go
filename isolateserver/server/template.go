// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed by the Apache v2.0 license that can be
// found in the LICENSE file.

package server

// This module includes all the HTML template processing code.

import (
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

var templates map[string]*template.Template = map[string]*template.Template{}

func init() {
	var baseDir string
	if fi, err := os.Stat("templates"); err == nil && fi.IsDir() {
		// When running the stand alone executable or running on AppEngine.
		baseDir = "templates/"
	} else {
		// When running tests locally.
		baseDir = "../templates/"
	}
	err := LoadTemplates(baseDir)
	if err != nil {
		panic(err)
	}
}

func LoadTemplates(baseDir string) error {
	files, err := filepath.Glob(baseDir + "*.html")
	if err != nil {
		return fmt.Errorf("Failed to glob %s: %s", baseDir, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("No template found in %s", baseDir)
	}
	// TODO(maruel): Permits a more arbitrary include tree.
	b, err := ioutil.ReadFile(baseDir + "skeleton.html")
	if err != nil {
		return fmt.Errorf("Failed to read base.html in %s", baseDir)
	}
	skeleton := string(b)
	for _, f := range files {
		name := filepath.Base(f)
		if name == "skeleton.html" {
			continue
		}
		b, err := ioutil.ReadFile(f)
		if err != nil {
			return fmt.Errorf("Failed to read %s: %s", f, err)
		}
		templates[name] = parseTemplate(skeleton, string(b))
	}
	return nil
}

func parseTemplate(src ...string) *template.Template {
	t := template.New("*")
	for _, s := range src {
		t = template.Must(t.Parse(s))
	}
	return t
}

func SendTemplate(w io.Writer, templateName string, obj interface{}) {
	// TODO(maruel): Inject AppVersion.
	templates[templateName].ExecuteTemplate(w, "base", obj)
}
