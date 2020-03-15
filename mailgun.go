package oauth2

import (
	"context"
	htmltmpl "html/template"
	"strings"
	texttmpl "text/template"

	"github.com/mailgun/mailgun-go"
	yall "yall.in"
)

type Mailgun struct {
	From          string
	Subject       string
	PlainTextTmpl *texttmpl.Template
	HTMLTmpl      *htmltmpl.Template
	Client        *mailgun.MailgunImpl
}

type tmplData struct {
	Code string
}

func (m Mailgun) SendMail(ctx context.Context, email, code string) error {
	log := yall.FromContext(ctx)
	log = log.WithField("email", email)
	var textBody, htmlBody strings.Builder
	data := tmplData{
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
	_, id, err := m.Client.Send(msg)
	if err != nil {
		return err
	}
	log = log.WithField("mailgun_msg_id", id)
	log.Debug("sent email")
	return nil
}
