# Multi-User-Blog project
Project created as a part of the Udacity.com Full Stack Nanodegree.
Features a simple blog structure with Registration/Login/Logout/Comments/Edit/Like system
Also removals.

Very brief usage of CSS.

## Live Demo
For a preview please visit this link: https://hello-world-165521.appspot.com/

## Running the blog locally on your computer.
<ol>
  <li> Download and install the Google App Engine SDK <a href="https://cloud.google.com/appengine/docs/python/download">HERE</a></li>
  <li> Clone Third Project from https://github.com/mikaeljan/UdacityThirdProject</li>
  <li> Change the working directory in the Terminal to where the project is downloaded</li>
  <li> Run `dev_appserver.py .`</li>
  <li> View the blog on http://localhost:8080/</li>
</ol>

# FILE MANIFEST

main.py, css.dir, templates.dir,, main.pyc, app.yaml, README.md

For any questions please feel free to contact me:<br />
mikael.janek@gmail.com

Notes to improve:
Add more CSS styling.
Implement modularization
Encapsulating the helper methods into a separate class
Add a constructor for login verification:
`def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user:
            self.redirect("/login")
        else:
            func(self, *args, **kwargs)
    return login`
