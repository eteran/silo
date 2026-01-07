package ui

import (
	"context"
	"fmt"
	"html"
	"io"

	"github.com/a-h/templ"
)

// Bucket represents a single S3 bucket for display.
type Bucket struct {
	Name         string
	CreationDate string
}

// Object represents a single object within a bucket for display.
type Object struct {
	Key          string
	Size         int64
	LastModified string
}

// Layout renders a full HTML page with a title and body component.
func Layout(title string, body templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, err := io.WriteString(w, "<!DOCTYPE html><html lang=\"en\">")
		if err != nil {
			return err
		}

		// Head
		_, err = io.WriteString(w, "<head><meta charset=\"utf-8\">")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "<title>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, html.EscapeString(title))
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</title>")
		if err != nil {
			return err
		}
		// Minimal modern CSS framework (Pico.css) via CDN.
		_, err = io.WriteString(w, "<link rel=\"stylesheet\" href=\"https://unpkg.com/@picocss/pico@2/css/pico.min.css\">")
		if err != nil {
			return err
		}
		// HTMX via CDN.
		_, err = io.WriteString(w, "<script src=\"https://unpkg.com/htmx.org@1.9.12\" integrity=\"sha384-srD8tA5lZgUlAXb/DvBy1UG775H8sG8vyXK3w63U1zrtRXkuTDIaTzGvX2UksI0M\" crossorigin=\"anonymous\"></script>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "</head>")
		if err != nil {
			return err
		}

		// Body with global htmx boost for links/forms.
		_, err = io.WriteString(w, "<body hx-boost=\"true\"><main class=\"container\">")
		if err != nil {
			return err
		}

		if err := body.Render(ctx, w); err != nil {
			return err
		}

		_, err = io.WriteString(w, "</main></body></html>")
		return err
	})
}

// BucketsPage renders the list of buckets.
func BucketsPage(buckets []Bucket) templ.Component {
	return Layout("Silo Browser - Buckets", templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, err := io.WriteString(w, "<section><header><h1>Silo Buckets</h1>")
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "<p>Browse buckets and objects via the S3-compatible API.</p></header>")
		if err != nil {
			return err
		}

		if len(buckets) == 0 {
			_, err = io.WriteString(w, "<p>No buckets found.</p></section>")
			return err
		}

		_, err = io.WriteString(w, "<table><thead><tr><th>Name</th><th>Created</th></tr></thead><tbody>")
		if err != nil {
			return err
		}

		for _, b := range buckets {
			row := fmt.Sprintf("<tr><td><a href=\"/bucket/%s\">%s</a></td><td>%s</td></tr>", html.EscapeString(b.Name), html.EscapeString(b.Name), html.EscapeString(b.CreationDate))
			_, err = io.WriteString(w, row)
			if err != nil {
				return err
			}
		}

		_, err = io.WriteString(w, "</tbody></table></section>")
		return err
	}))
}

// ObjectsPage renders the list of objects for a single bucket.
func ObjectsPage(bucket string, objects []Object) templ.Component {
	return Layout("Silo Browser - "+bucket, templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		_, err := io.WriteString(w, "<section><header>")
		if err != nil {
			return err
		}
		title := fmt.Sprintf("<h1>Bucket: %s</h1>", html.EscapeString(bucket))
		_, err = io.WriteString(w, title)
		if err != nil {
			return err
		}
		_, err = io.WriteString(w, "<p><a href=\"/\">&larr; Back to buckets</a></p></header>")
		if err != nil {
			return err
		}

		if len(objects) == 0 {
			_, err = io.WriteString(w, "<p>No objects in this bucket.</p></section>")
			return err
		}

		_, err = io.WriteString(w, "<table><thead><tr><th>Key</th><th>Size (bytes)</th><th>Last Modified</th></tr></thead><tbody>")
		if err != nil {
			return err
		}

		for _, o := range objects {
			row := fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%s</td></tr>", html.EscapeString(o.Key), o.Size, html.EscapeString(o.LastModified))
			_, err = io.WriteString(w, row)
			if err != nil {
				return err
			}
		}

		_, err = io.WriteString(w, "</tbody></table></section>")
		return err
	}))
}
