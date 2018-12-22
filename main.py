# main.py

#/***************************************************************************
# *   Copyright (C) 2018 Daniel Mueller (deso@posteo.net)                   *
# *                                                                         *
# *   This program is free software: you can redistribute it and/or modify  *
# *   it under the terms of the GNU General Public License as published by  *
# *   the Free Software Foundation, either version 3 of the License, or     *
# *   (at your option) any later version.                                   *
# *                                                                         *
# *   This program is distributed in the hope that it will be useful,       *
# *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
# *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
# *   GNU General Public License for more details.                          *
# *                                                                         *
# *   You should have received a copy of the GNU General Public License     *
# *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
# ***************************************************************************/

from argparse import (
  ArgumentParser,
)
from contextlib import (
  suppress,
)
from hmac import (
  new as newHmac,
  compare_digest as compareHmac,
)
from http.server import (
  BaseHTTPRequestHandler,
  HTTPServer,
  HTTPStatus,
)
from json import (
  loads as loadJson,
)
from re import (
  sub,
)
from ssl import (
  wrap_socket,
)
from subprocess import (
  check_call,
)
from sys import (
  argv,
)
from tempfile import (
  TemporaryDirectory,
)
from urllib.parse import (
  urlsplit as splitUrl,
  urlunsplit as unsplitUrl,
)


__version__ = "0.1"


class HttpError(RuntimeError):
  """A class for objects used to signify authentication errors."""
  def __init__(self, status, error):
    super().__init__(error)
    self.status = status


class GitRepo:
  """This class manages a Git repository in some given directory."""
  def __init__(self, git, dir_):
    """Create a new Repository object."""
    self._git = git
    self._dir_ = dir_

  def git(self, *args, **kwargs):
    """Run a git command."""
    return check_call([self._git, "-C", self._dir_, *args], env={}, **kwargs)

  def __getattr__(self, name):
    """Invoke a git command."""
    def replace(match):
      """Replace an upper case char with a dash followed by a lower case version of it."""
      s, = match.groups()
      return "-%s" % s.lower()

    command = sub("([A-Z])", replace, name)
    return lambda *args, **kwargs: self.git(command, *args, **kwargs)

  def __enter__(self, *args, **kwargs):
    """The block enter handler returns an initialized Repository object."""
    self.init("--quiet", *args, **kwargs)
    return self

  def __exit__(self, type_, value, traceback):
    """The block exit handler destroys the git repository."""
    pass


class GithubPullRequestHandler(BaseHTTPRequestHandler):
  """An HTTP request handler that handles notification requests from Github web hooks.

    Details can be found at https://developer.github.com/v3/.
  """
  # Python defaults to HTTP/0.9. We have no experience with that. Let's just
  # avoid it and try with a higher version from the start. Compared to 1.0, 1.1
  # seemingly offers keep alives and stuff we don't need. So let's not bother
  # with that.
  default_request_version = "HTTP/1.0"
  server_version = "GithubPullRequestMirror/%s" % __version__

  def _calculateHmac(self, body):
    """Calculate the HMAC of the HTTP request's body."""
    # The hashing method to use. Github uses SHA-1.
    HMAC_DIGEST = "sha1"

    hmac = newHmac(self.secret.encode(), msg=body, digestmod=HMAC_DIGEST)
    return "sha1=" + hmac.hexdigest()

  def _verify_signature(self, body):
    """Verify that the request comes from Github by checking the "signature".

      The signature is contained in a special header field, X-Hub-Signature,
      and is essentially an HMAC over a pre-shared secret.
    """
    # HTTP header field name containing Github's "signature".
    HDR_SIGNATURE = "X-Hub-Signature"

    sig = self.headers.get(HDR_SIGNATURE)
    if sig is None:
      raise HttpError(HTTPStatus.UNAUTHORIZED, "signature is missing")

    expct = self._calculateHmac(body)

    if not compareHmac(sig, expct):
      raise HttpError(HTTPStatus.UNAUTHORIZED, "HMAC verification failed")

  def _handleRequest(self, body):
    """Handle a Github HTTP request."""
    type_ = self.headers.get("content-type")
    if type_ != "application/json":
      raise HttpError(HTTPStatus.BAD_REQUEST, "invalid Content-Type")

    content = loadJson(body)
    if "pull_request" not in content:
      raise RuntimeError("received unsupported event type")

    if content["action"] == "closed":
      return

    src_repo = content["pull_request"]["head"]["repo"]["clone_url"]
    src_branch = content["pull_request"]["head"]["ref"]

    dst_repo = content["repository"]["clone_url"]
    # Pull requests get their own namespace that "normal" branches would not
    # use. This prevents malicious overwrites.
    dst_branch = "pull-request/%s" % src_branch

    # "Inject" our authentication information into the URL, as that's how git
    # can understand it.
    split = list(splitUrl(dst_repo))
    split[1] = "%s:%s@%s" % (self.user, self.token, split[1])
    dst_repo = unsplitUrl(split)

    with TemporaryDirectory() as dir_,\
         GitRepo(self.git, dir_) as repo:
      repo.fetch("--quiet", "--force", "--no-recurse-submodules",
                 src_repo, ":".join((src_branch, dst_branch)))
      repo.push("--quiet", "--force", dst_repo, "+%s" % dst_branch)

  def do_POST(self):
    """Handle an HTTP POST request."""
    try:
      size = self.headers.get("content-length")
      if size is None:
        raise HttpError(HTTPStatus.LENGTH_REQUIRED, "Content-Length field not present")

      # Github has a maximum request size of 25 MiB for certain API
      # calls. There is no reason a notification here would be that
      # large, so cut off excessively sized requests earlier to prevent
      # DoS at least to a certain degree.
      if int(size) > 1 * 1024 * 1024:
        raise HttpError(HTTPStatus.PAYLOAD_TOO_LARGE, "request is too large")

      # We are going to need the body at least twice and we cannot seek
      # on the provided "file" object. So just read it in full.
      body = self.rfile.read()
      self._verify_signature(body)
      self._handleRequest(body)
    except HttpError as e:
      self.send_error(e.status, str(e))
    except Exception as e:
      self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
      # Re-raise exception in the hope that somebody will notice and
      # investigate. It will only be available locally. We deliberately
      # do not send back the full backtrace to prevent unnecessary
      # leakage of information (file system layout, user name etc.).
      raise


def parseArgs(args):
  """Create and initialize an argument parser, ready for use."""
  parser = ArgumentParser()
  parser.add_argument(
    "user", action="store", metavar="user",
    help="The Github user name to use.",
  )
  parser.add_argument(
    "token", action="store", metavar="token",
    help="The authentication token to use. The token needs to have the "
         "'public_repo' capability. See https://github.com/settings/tokens.",
  )
  parser.add_argument(
    "secret", action="store", metavar="secret",
    help="The pre-shared secret used for the web hook. This secret will "
         "be used to authenticate incoming requests.",
  )
  parser.add_argument(
    "cert", action="store", metavar="tls-cert",
    help="Path to the TLS certificate to use.",
  )
  parser.add_argument(
    "key", action="store", metavar="tls-key",
    help="Path to the TLS key file to use.",
  )
  parser.add_argument(
    "--git", action="store", default="git", dest="git", metavar="git",
    help="The git executable to invoke."
  )
  parser.add_argument(
    "--port", action="store", type=int, default=443, dest="port", metavar="port",
    help="The TCP port to listen on (default: 443).",
  )
  return parser.parse_args(args)


def main(args):
  """Parse the arguments and respond to Githup HTTP notifications."""
  ns = parseArgs(args[1:])

  handler = GithubPullRequestHandler
  handler.git = ns.git
  handler.user = ns.user
  handler.token = ns.token
  handler.secret = ns.secret

  httpd = HTTPServer(("", ns.port), handler)
  httpd.socket = wrap_socket(httpd.socket, certfile=ns.cert,
                             keyfile=ns.key, server_side=True)

  with suppress(KeyboardInterrupt):
    httpd.serve_forever()


if __name__ == "__main__":
  exit(main(argv))
