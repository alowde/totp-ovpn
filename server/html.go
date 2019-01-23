package server

import (
	"html/template"
	"net/http"
)

var head = `
<head>
	<style>
	.lightbox {
		border-style: solid;
		border-width: 1px;
		border-color: rgba(0,0,0,0.25);
		margin: 0 auto;
		width: 300px;
		box-shadow: 0 14px 28px rgba(0,0,0,0.25), 0 10px 10px rgba(0,0,0,0.22);
		text-align: center;
		padding: 10px;
	}
	.inset {
		display: inline-block;
	}
	</style>
</head>
<body>
	<div class="lightbox">
		<div class="inset">`

var tail = `
		</div>
	</div>
</body>
`

var qrContent = `
<img src="/qr?user={{.User}}" /><br>
		Text here centered`

func qrPage(w http.ResponseWriter, user string) error {

	params := struct {
		Title string
		User  string
	}{"Enroll a New User", user}

	t := template.New("qrPage")
	t, _ = t.Parse(head + qrContent + tail)
	return t.Execute(w, params)

}

/*
var csrInputHTML = `
    	<img src="/qr?user=cat"</img><br>
    	Text here centered
`*/
