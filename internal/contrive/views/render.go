package views

import (
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"time"
)

var Templates *template.Template

var (
	templateIncludeFiles []string
)

// OpenGraph for Facebook unfurl
type OpenGraph struct {
	Title       string
	Image       string
	Description string
}

func init() {
	includeFiles, err := filepath.Glob("templates/includes/*.html")
	if err != nil {
		log.Fatal(err)
	}

	templateIncludeFiles = append(includeFiles, "templates/layout/layout.html")
}

func newPage(r *http.Request, title string) map[string]interface{} {
	p := make(map[string]interface{})
	p["Title"] = title
	p["Header"] = ""
	return p
}

func cache(w http.ResponseWriter, cacheTime time.Duration) {
	if cacheTime.Seconds() > float64(0) {
		w.Header().Set("Cache-Control", "max-age:"+strconv.Itoa(int(cacheTime.Seconds()))+", public")
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Expires", time.Now().UTC().Add(cacheTime).Format(http.TimeFormat))
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
	}
}

func renderJSON(w http.ResponseWriter, v interface{}, cacheTime time.Duration) error {
	cache(w, cacheTime)
	return json.NewEncoder(w).Encode(v)
}

func renderText(w http.ResponseWriter, s []byte, cacheTime time.Duration) error {
	cache(w, cacheTime)
	_, err := w.Write(s)
	return err
}

func renderTemplate(w http.ResponseWriter, name string, cacheTime time.Duration, data interface{}) error {
	cache(w, cacheTime)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	mainTemplate := template.Must(template.New("base").Funcs(template.FuncMap{
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values) == 0 {
				return nil, errors.New("invalid dict call")
			}

			dict := make(map[string]interface{})

			for i := 0; i < len(values); i++ {
				key, isset := values[i].(string)
				if !isset {
					if reflect.TypeOf(values[i]).Kind() == reflect.Map {
						m := values[i].(map[string]interface{})
						for i, v := range m {
							dict[i] = v
						}
					} else {
						return nil, errors.New("dict values must be maps")
					}
				} else {
					i++
					if i == len(values) {
						return nil, errors.New("specify the key for non array values")
					}
					dict[key] = values[i]
				}

			}
			return dict, nil
		},
	}).ParseFiles("templates/layout/layout.html"))

	t, err := mainTemplate.Clone()
	if err != nil {
		log.Fatal(err)
	}

	templates := append(templateIncludeFiles, "templates/"+name)
	t = template.Must(
		t.ParseFiles(templates...),
	)

	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		httpErrCode(w, err, http.StatusInternalServerError)
		return err
	}

	return nil
}

func httpErrCode(w http.ResponseWriter, err error, code int) {
	if err != nil {
		log.Printf("http error %s", err)
	}
	http.Error(w, http.StatusText(code), code)
}

func httpErr(w http.ResponseWriter, err error) {
	log.Printf("http error %s", err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
