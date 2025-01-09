from flask import render_template, request

from config import app


@app.route('/')
def index():
    return render_template('home/index.html')


@app.errorhandler(400)
def badrequest(error):
    return render_template('errors/badrequest.html'), 400


@app.errorhandler(404)
def notfound(error):
    return render_template('errors/notfound.html'), 404


@app.errorhandler(500)
def internalserver(error):
    return render_template('errors/internalserver.html'), 500


@app.errorhandler(501)
def notimplemented(error):
    return render_template('errors/notimplemented.html'), 501


@app.errorhandler(429)
def ratelimiterror(error):
    return render_template('errors/ratelimit.html'), 429


@app.before_request
def firewallcheck():
    sql_keywords = ["Union", "Select", "Insert", "Drop", "Alter", ";", "'", "`"]
    xss_keywords = ["<script>", "<iframe>", "%3Cscript%3E", "%3Ciframe%3E"]
    path_traversal_patterns = ["../", "..", "%2e%2e%2f", "%2e%2e%5c"]
    attacks = {"An SQL": sql_keywords, "An XSS": xss_keywords, "A Path traversal": path_traversal_patterns}

    for attacktype in attacks:
        for attack in attacks[attacktype]:
            if attack in (request.url) or attack in (request.query_string.decode()) or attack in request.form.values():
                return render_template('errors/attack.html', label=attacktype)


if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))
