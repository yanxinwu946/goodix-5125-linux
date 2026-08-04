// Goodix Tls driver for libfprint

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <natasha@natashaee.me>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "drivers_api.h"
#include "fp-device.h"
#include "fpi-device.h"
#include "glibconfig.h"
#include "goodix.h"
#include "goodixtls.h"

static GError *
err_from_ssl (void)
{
  GError *err = malloc (sizeof (GError));
  unsigned long code = ERR_get_error ();

  err->code = code;
  const char *msg = ERR_reason_error_string (code);

  err->message = malloc (strlen (msg));
  strcpy (err->message, msg);
  return err;
}

// non-zero, device-specific session PSK (e.g. the 5125/5F10) call goodix_tls_set_psk()
// before bringing TLS up.
// NOTE: module-global, not per-device. Assumes a single Goodix TLS reader is active
// at a time, which holds for these drivers. Two such readers with different session
// PSKs would clash; make this per-instance before supporting that.
static unsigned char goodix_tls_psk[64] = {0};
static unsigned int  goodix_tls_psk_len = 32;

void
goodix_tls_set_psk (const guint8 *psk, unsigned int len)
{
  if (len > sizeof (goodix_tls_psk))
    {
      g_warning ("goodix: PSK of %u bytes truncated to %zu", len, sizeof (goodix_tls_psk));
      len = sizeof (goodix_tls_psk);
    }
  memcpy (goodix_tls_psk, psk, len);
  goodix_tls_psk_len = len;
}

static unsigned int
tls_server_psk_server_callback (SSL           *ssl,
                                const char    *identity,
                                unsigned char *psk,
                                unsigned int   max_psk_len)
{
  const unsigned int len = goodix_tls_psk_len;

  fp_dbg ("PSK WANTED %d, identity=%s", max_psk_len, identity ? identity : "(null)");
  if (len > max_psk_len)
    {
      fp_err ("max psk length (%d) too short (needs %d)", max_psk_len, len);
      return 0;
    }

  memcpy (psk, goodix_tls_psk, len);
  fp_dbg ("PSK returned %u bytes", len);
  return len;
}

static SSL_CTX *
tls_server_create_ctx (void)
{
  const SSL_METHOD *method;

  method = TLS_server_method ();

  SSL_CTX *ctx = SSL_CTX_new (method);

  if (!ctx)
    return NULL;

  return ctx;
}

static void
tls_server_config_ctx (SSL_CTX *ctx)
{
  SSL_CTX_set_ecdh_auto (ctx, 1);
  SSL_CTX_set_dh_auto (ctx, 1);
  SSL_CTX_set_cipher_list (ctx, "ALL");
  SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_server_callback (ctx, tls_server_psk_server_callback);
}

int
goodix_tls_client_write (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  return write (self->client_fd, data, length * sizeof (guint8));
}
int
goodix_tls_client_read (GoodixTlsServer *self, guint8 *data, guint16 length)
{
  return read (self->client_fd, data, length * sizeof (guint8));
}

int
goodix_tls_server_read (GoodixTlsServer *self, guint8 *data,
                        guint32 length, GError **error)
{
  if (self->ssl_layer)
    {
      int retr = SSL_read (self->ssl_layer, data, length * sizeof (guint8));
      if (retr <= 0)
        *error = err_from_ssl ();
      return retr;
    }
  // s_server mode: read decrypted output from stdout pipe (sock_fd)
  int retr = read (self->sock_fd, data, length * sizeof (guint8));
  if (retr <= 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "failed to read from s_server stdout: %s", strerror (errno));
    }
  return retr;
}

static void
tls_config_ssl (SSL *ssl)
{
  SSL_set_min_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_max_proto_version (ssl, TLS1_2_VERSION);
  SSL_set_psk_server_callback (ssl, tls_server_psk_server_callback);
  SSL_set_cipher_list (ssl, "PSK-AES128-GCM-SHA256:@SECLEVEL=0");
}

static void *
goodix_tls_init_serve (void *me)
{
  GoodixTlsServer *self = me;

  fp_dbg ("TLS server waiting to accept...");
  int retr = SSL_accept (self->ssl_layer);

  self->accept_ok = (retr > 0);
  self->accept_error_code = (retr > 0) ? 0 : ERR_get_error ();

  fp_dbg ("TLS server accept done");
  if (retr <= 0)
    fp_err ("server ready failed: %s",
            ERR_reason_error_string (self->accept_error_code));
  else
    fp_dbg ("TLS connection ready");
  return NULL;
}

gboolean
goodix_tls_server_accept_ok (GoodixTlsServer *self)
{
  return self->accept_ok;
}

unsigned long
goodix_tls_server_accept_error (GoodixTlsServer *self)
{
  return self->accept_error_code;
}

gboolean
goodix_tls_server_deinit (GoodixTlsServer *self, GError **error)
{
  if (self->ssl_layer)
    {
      SSL_shutdown (self->ssl_layer);
      SSL_free (self->ssl_layer);
    }

  if (self->client_fd >= 0)
    close (self->client_fd);
  if (self->sock_fd >= 0)
    close (self->sock_fd);

  if (self->ssl_ctx)
    SSL_CTX_free (self->ssl_ctx);

  if (self->serve_thread)
    pthread_join (self->serve_thread, NULL);

  // Terminate external s_server if we started one
  if (self->sserver_pid > 0)
    {
      kill (self->sserver_pid, SIGTERM);
      int status;
      waitpid (self->sserver_pid, &status, WNOHANG);
      self->sserver_pid = 0;
    }

  return TRUE;
}

gboolean
goodix_tls_server_init (GoodixTlsServer *self, GError **error)
{
  SSL_load_error_strings ();
  OpenSSL_add_ssl_algorithms ();
  SSL_library_init ();
  self->sserver_pid = 0;
  self->accept_ok = FALSE;
  self->accept_error_code = 0;
  self->ssl_ctx = NULL;
  self->ssl_layer = NULL;
  self->sock_fd = -1;
  self->client_fd = -1;
  self->serve_thread = 0;

  char psk_hex[128] = {0};
  for (unsigned int i = 0; i < goodix_tls_psk_len && i < 64; i++)
    sprintf (psk_hex + i * 2, "%02x", goodix_tls_psk[i]);

  int port = 14433;
  char port_str[16];
  sprintf (port_str, "%d", port);

  int stdout_pipe[2] = {0, 0};
  if (pipe (stdout_pipe) < 0)
    {
      g_set_error (error, G_FILE_ERROR, errno,
                   "failed to create pipe: %s", strerror (errno));
      return FALSE;
    }

  pid_t pid = fork ();
  if (pid == 0)
    {
      close (stdout_pipe[0]);
      int devnull = open ("/dev/null", O_RDWR);
      dup2 (devnull, STDIN_FILENO);
      dup2 (stdout_pipe[1], STDOUT_FILENO);
      dup2 (devnull, STDERR_FILENO);
      close (devnull);
      close (stdout_pipe[1]);
      execlp ("openssl", "openssl", "s_server",
              "-nocert", "-psk", psk_hex,
              "-port", port_str,
              "-quiet", "-cipher", "PSK-AES128-GCM-SHA256",
              "-tls1_2", NULL);
      _exit (1);
    }
  close (stdout_pipe[1]);

  if (pid < 0)
    {
      close (stdout_pipe[0]);
      g_set_error (error, G_FILE_ERROR, errno,
                   "failed to fork s_server: %s", strerror (errno));
      return FALSE;
    }
  self->sserver_pid = pid;
  self->sock_fd = stdout_pipe[0];

  int sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0) sock = socket (AF_INET6, SOCK_STREAM, 0);
  if (sock < 0)
    {
      close (stdout_pipe[0]); kill (pid, SIGTERM);
      g_set_error (error, G_FILE_ERROR, errno, "socket: %s", strerror (errno));
      return FALSE;
    }

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  int connected = 0;
  for (int retry = 0; retry < 50; retry++)
    {
      if (connect (sock, (struct sockaddr *) &addr, sizeof (addr)) == 0)
        { connected = 1; break; }
      usleep (100000);
    }

  if (!connected)
    {
      struct sockaddr_in6 addr6 = {0};
      addr6.sin6_family = AF_INET6;
      addr6.sin6_port = htons (port);
      addr6.sin6_addr = in6addr_loopback;
      for (int retry = 0; retry < 50; retry++)
        {
          if (connect (sock, (struct sockaddr *) &addr6, sizeof (addr6)) == 0)
            { connected = 1; break; }
          usleep (100000);
        }
    }

  if (!connected)
    {
      close (sock); close (stdout_pipe[0]); kill (pid, SIGTERM);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                   "failed to connect to s_server on port %d", port);
      return FALSE;
    }

  self->client_fd = sock;
  self->accept_ok = TRUE;
  self->accept_error_code = 0;
  fp_dbg ("s_server started (pid %d, fd %d, stdout %d)", pid, sock, stdout_pipe[0]);
  return TRUE;
}
