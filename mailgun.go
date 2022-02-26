package oauth2

import (
	"context"
	htmltmpl "html/template"
	"strings"
	texttmpl "text/template"

	"github.com/mailgun/mailgun-go/v4"
	yall "yall.in"
)

// Mailgun is an implementation of the `emailer` interface that sends mail
// using the Mailgun API.
type Mailgun struct {
	From          string
	Subject       string
	PlainTextTmpl *texttmpl.Template
	HTMLTmpl      *htmltmpl.Template
	Client        *mailgun.MailgunImpl
}

// MailgunTemplateData is the package of data that gets passed to the
// text/template and html/template Execute methods and is available within the
// templates.
type MailgunTemplateData struct {
	// The authorization code that needs to be exchanged for a session.
	Code string
}

// SendMail sends the specified `code` to the specified `email` using Mailgun's
// API. The mail will have `m.Subject` as a subject and use `m.PlainTextTmpl`
// and `m.HTMLTmpl` as the plain-text and HTML bodies, respectively. The
// templates are given a `MailgunTemplateData` variable as their `data`
// argument.
func (m Mailgun) SendMail(ctx context.Context, email, code string) error {
	log := yall.FromContext(ctx)
	log = log.WithField("email", email)
	var textBody, htmlBody strings.Builder
	data := MailgunTemplateData{
		Code: code,
	}
	err := m.PlainTextTmpl.Execute(&textBody, data)
	if err != nil {
		return err
	}
	err = m.HTMLTmpl.Execute(&htmlBody, data)
	if err != nil {
		return err
	}
	msg := m.Client.NewMessage(
		m.From,
		m.Subject,
		textBody.String(),
		email,
	)
	msg.SetTracking(false)
	msg.SetHtml(htmlBody.String())
	_, id, err := m.Client.Send(ctx, msg)
	if err != nil {
		return err
	}
	log = log.WithField("mailgun_msg_id", id)
	log.Debug("sent email")
	return nil
}
