import base64
import os
import warnings

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ipywidgets import DOMWidget
from traitlets import Unicode, observe


class SecretsWidget(DOMWidget):
    """A notebook widget that stores and retrieves a secret via the JupyterLab
    secrets manager.

    The secret value is entered by the user in the rendered input field and
    delivered to the Python kernel via an encrypted channel (ECDH key
    agreement + AES-256-GCM).  The value is also persisted in the active
    secrets-manager connector so it survives re-renders within the same
    session.

    Parameters
    ----------
    label:
        Text label shown next to the input field.
    secret_id:
        Unique key used to store/retrieve the secret in the manager.  Two
        widgets sharing the same ``secret_id`` will share the same stored
        value.

    Example
    -------
    >>> from jupyter_secrets_manager import SecretsWidget
    >>> w = SecretsWidget(label='OpenAI API key', secret_id='openai-api-key')
    >>> display(w)
    >>> # user types the key in the rendered widget …
    >>> api_key = w.value
    """

    _model_name = Unicode('SecretsModel').tag(sync=True)
    _model_module = Unicode('jupyter-secrets-manager').tag(sync=True)
    _model_module_version = Unicode('0.5.0').tag(sync=True)
    _view_name = Unicode('SecretsView').tag(sync=True)
    _view_module = Unicode('jupyter-secrets-manager').tag(sync=True)
    _view_module_version = Unicode('0.5.0').tag(sync=True)

    label = Unicode('Secret').tag(sync=True)
    secret_id = Unicode('').tag(sync=True)

    # Not synced: transmitted only via encrypted custom messages.
    value = Unicode('')

    def __init__(self, **kwargs):
        # Extract value before passing to super to avoid traitlet sync.
        initial_value = kwargs.pop('value', '')
        super().__init__(**kwargs)

        self._private_key = ec.generate_private_key(SECP256R1())
        self._challenge_key: bytes | None = None
        self._enc_key: bytes | None = None
        # State machine: init → key_sent → authenticated
        self._state = 'init'
        # Pending value to send once authenticated.
        self._pending_value: str | None = initial_value if initial_value else None
        # Flag to break the observe→send→observe loop.
        self._value_from_frontend = False

        self.on_msg(self._handle_msg)

    @observe('value')
    def _on_value_set(self, change: dict) -> None:
        if self._value_from_frontend:
            return
        v = change['new']
        if self._state == 'authenticated':
            self._send_encrypted('set_value', v)
        else:
            self._pending_value = v

    def _handle_msg(self, widget, content: dict, buffers) -> None:
        msg_type = content.get('type')
        if msg_type == 'ready' and self._state == 'init':
            self._start_handshake()
        elif msg_type == 'challenge' and self._state == 'key_sent':
            self._handle_challenge(content)
        elif msg_type == 'value' and self._state == 'authenticated':
            self._handle_value(content)

    def _start_handshake(self) -> None:
        pub_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.send({
            'type': 'public_key',
            'key': base64.b64encode(pub_bytes).decode(),
        })
        self._state = 'key_sent'

    def _handle_challenge(self, content: dict) -> None:
        try:
            ephemeral_pub_bytes = base64.b64decode(content['ephemeral_pub'])
            nonce = base64.b64decode(content['nonce'])

            ephemeral_pub = EllipticCurvePublicKey.from_encoded_point(
                SECP256R1(), ephemeral_pub_bytes
            )
            shared = self._private_key.exchange(ECDH(), ephemeral_pub)

            self._challenge_key = HKDF(
                algorithm=hashes.SHA256(), length=32,
                salt=b'\x00' * 32, info=b'challenge',
            ).derive(shared)
            self._enc_key = HKDF(
                algorithm=hashes.SHA256(), length=32,
                salt=b'\x00' * 32, info=b'encryption',
            ).derive(shared)

            h = crypto_hmac.HMAC(self._challenge_key, hashes.SHA256())
            h.update(nonce)
            sig = h.finalize()

            self.send({
                'type': 'challenge_response',
                'signature': base64.b64encode(sig).decode(),
            })
            self._state = 'authenticated'

            if self._pending_value is not None:
                self._send_encrypted('set_value', self._pending_value)
                self._pending_value = None

        except Exception as e:
            warnings.warn(f'SecretsWidget: handshake failed: {e}')

    def _handle_value(self, content: dict) -> None:
        try:
            iv = base64.b64decode(content['iv'])
            ciphertext = base64.b64decode(content['ciphertext'])
            plaintext = AESGCM(self._enc_key).decrypt(iv, ciphertext, None)
            self._value_from_frontend = True
            try:
                self.value = plaintext.decode('utf-8')
            finally:
                self._value_from_frontend = False
        except Exception as e:
            warnings.warn(f'SecretsWidget: failed to decrypt value: {e}')

    def _send_encrypted(self, msg_type: str, value: str) -> None:
        try:
            iv = os.urandom(12)
            ciphertext = AESGCM(self._enc_key).encrypt(
                iv, value.encode('utf-8'), None
            )
            self.send({
                'type': msg_type,
                'iv': base64.b64encode(iv).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
            })
        except Exception as e:
            warnings.warn(f'SecretsWidget: failed to encrypt value: {e}')
