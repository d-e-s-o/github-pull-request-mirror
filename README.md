github-pull-request-mirror
==========================

`github-pull-request-mirror` is a program that can act as the end point
to a [Github][github] web hook. Upon receiving notification that a pull
request to one of the user's repositories was made, it creates a mirror
of the branch to be merged in in the repository the pull request was
made in.


Motivation
----------

Github does not come with its own Continuous Integration (CI)
pipeline. There are various applications out there that provide such a
service, each with different trade-offs. The [Gitlab][gitlab] CI
pipeline was found to be very flexible and more configurable than most
services.

The way the Gitlab pipeline works is by mirroring (i.e., cloning) an
existing external repository (e.g., one hosted on Github). That is, it
registers a web hook with Github to be notified of new commits in the
repository and will update the cloned repository state in Gitlab
accordingly.

Unfortunately, this mechanism does not work for pull requests. A pull
request on Github does **not** create a local branch in the repository
the merge is supposed to happen in. Without such a branch Gitlab's
mirroring repository will never get the to-be-merged code and, hence,
the pipeline cannot run on it.

`github-pull-request-mirror` bridges this gap by acting as a Github web
hook endpoint in itself. Once it gets notified that a pull request on
the Github repository occurred, it will create a mirror of the branch
that is to be merged in in the local repository. This way, Gitlab will
be able to see a new branch/commit and can ensure to test it via its CI
pipeline.


Setup
-----

### Github Configuration

There are two configurations that need to happen in order to register
this program on the Github side.
1. An access token needs to be generated through which the program can
   push a new branch to a user's repository. This can be created through
   the [Github UI][github-tokens]. The token needs to have at least
   access to the `public_repo` scope.
2. A new web hook needs to be added that sends a `POST` request to a
   server running `github-pull-request-mirror`. Such a web hook needs to
   be added on a per repository basis. That can be done at
   `https://github.com/<user>/<repo>/settings/hooks`.
   The fields should be set as follows:
   - `Payload URL` is typically `https://<dns-of-server>:<port>`.
   - `Content-Type` should be set to `application/json`.
   - `Secret` can be any secret of your choosing. The same secret will
     need to be supplied to the program (see [Usage](#usage))
   - If you are not in possession of a certificate signed by a publicly
     trusted certificate authority, you will have to create a
     self-signed certificate (see [Server Setup](#server-setup)) and
     disable `SSL verification`.
   - The hook should be triggered only on `Pull requests` events. While
     other events should not cause problems, they result in unnecessary
     traffic.

### Server Setup
`github-pull-request-mirror` needs to run on some publicly reachable
server. The program unconditionally uses an SSL enabled HTTP server. As
such, it requires a valid certificate to work with. If a certificate
signed by a trusted CA is not available, a self-signed certificate can
be used. This way all traffic is still encrypted, but Github will not be
able to verify the authenticity of the host the request is sent to.

A self-signed certificate can be created using OpenSSL, like so:
```sh
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -nodes
```

Note that `-nodes` disables password protection of the associated key,
which allows for easily using this certificate in a non-interactive
context.
Using the above command, the certificate does not expire. Use the
optional `-days` argument in order to limit its lifetime. Please refer
to your favorite OpenSSL tutorial for a more comprehensive reference.

### Usage

A typical invocation looks as follows:
```sh
python3 main.py <user> <token> <secret> cert.pem key.pem
```

Here `<user>` is the user's Github user name. `<token>` is a token
generated through the aforementioned [Github UI][github-tokens].
`<secret>` is the secret configured for the web hook handling pull
requests.

Note that by virtue of being a daemon style process, the program should
likely run under some sort of watchdog in case an error brings it down.


Support
-------

The module is tested with Python 3. There is no work going on to ensure compatibility with Python 2.


[github]: https://github.com/
[github-tokens]: https://github.com/settings/tokens
[gitlab]: https://gitlab.com/
