import { DOMWidgetModel, DOMWidgetView } from '@jupyter-widgets/base';

import { ISecretsManager } from './token';

export const MODULE_NAME = 'jupyter-secrets-manager';
export const MODULE_VERSION = '0.5.0';

const NAMESPACE = 'jupyter-secrets-manager:widget';

let _manager: ISecretsManager | null = null;
let _token: symbol | null = null;

export function setManager(manager: ISecretsManager, token: symbol): void {
  _manager = manager;
  _token = token;
}

export class SecretsModel extends DOMWidgetModel {
  defaults(): ReturnType<DOMWidgetModel['defaults']> {
    return {
      ...super.defaults(),
      _model_name: 'SecretsModel',
      _model_module: MODULE_NAME,
      _model_module_version: MODULE_VERSION,
      _view_name: 'SecretsView',
      _view_module: MODULE_NAME,
      _view_module_version: MODULE_VERSION,
      label: 'Secret',
      secret_id: ''
    };
  }

  static model_name = 'SecretsModel';
  static model_module = MODULE_NAME;
  static model_module_version = MODULE_VERSION;
  static view_name = 'SecretsView';
  static view_module = MODULE_NAME;
  static view_module_version = MODULE_VERSION;
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

function b64ToBuffer(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bufferToB64(buf: ArrayBufferLike | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

// ── Widget view ───────────────────────────────────────────────────────────────

export class SecretsView extends DOMWidgetView {
  render(): void {
    this.el.classList.add('jp-SecretsWidget');

    const label = document.createElement('label');
    label.className = 'jp-SecretsWidget-label';
    label.textContent = this.model.get('label') as string;

    const input = document.createElement('input');
    input.className = 'jp-SecretsWidget-input';
    input.placeholder = 'Enter secret…';

    this.el.appendChild(label);
    this.el.appendChild(input);
    this._input = input;

    if (_manager) {
      input.type = _manager.secretFieldsVisibility ? 'text' : 'password';
      this._onVisibilityChanged = (_: ISecretsManager, visible: boolean) => {
        input.type = visible ? 'text' : 'password';
      };
      _manager.fieldVisibilityChanged.connect(this._onVisibilityChanged);
    } else {
      input.type = 'password';
    }

    const secretId: string = this.model.get('secret_id');
    if (_manager && _token && secretId) {
      // No callback: the 'input' event dispatched by attach() covers pre-fill.
      _manager.attach(_token, NAMESPACE, secretId, input).catch(console.error);
    }

    // Buffer value until the handshake completes; fires on manager pre-fill too.
    input.addEventListener('input', () => {
      if (this._authenticated) {
        this._encryptAndSend(input.value).catch(console.error);
      } else {
        this._pendingValue = input.value;
      }
    });

    this.listenTo(this.model, 'change:label', () => {
      label.textContent = this.model.get('label') as string;
    });

    // Receive encrypted messages from Python.
    this.listenTo(this.model, 'msg:custom', (msg: Record<string, string>) => {
      this._handlePythonMsg(msg).catch(console.error);
    });

    // Signal readiness — Python responds with its public key.
    this.send({ type: 'ready' });
  }

  remove(): void {
    if (_manager) {
      if (this._onVisibilityChanged) {
        _manager.fieldVisibilityChanged.disconnect(this._onVisibilityChanged);
      }
      if (_token) {
        const secretId: string = this.model.get('secret_id');
        if (secretId) {
          _manager.detach(_token, NAMESPACE, secretId).catch(console.error);
        }
      }
    }
    super.remove();
  }

  // ── Handshake protocol ────────────────────────────────────────────────────

  private async _handlePythonMsg(msg: Record<string, string>): Promise<void> {
    switch (msg.type) {
      case 'public_key':
        await this._doHandshake(msg.key);
        break;
      case 'challenge_response':
        await this._verifyChallengeResponse(msg.signature);
        break;
      case 'set_value':
        if (this._authenticated) {
          const value = await this._decrypt(msg.iv, msg.ciphertext);
          if (this._input) {
            this._input.value = value;
          }
          if (_manager && _token) {
            const secretId: string = this.model.get('secret_id');
            if (secretId) {
              _manager
                .set(_token, NAMESPACE, secretId, {
                  namespace: NAMESPACE,
                  id: secretId,
                  value
                })
                .catch(console.error);
            }
          }
        }
        break;
    }
  }

  private async _doHandshake(pythonPubKeyB64: string): Promise<void> {
    const pythonPubKey = await crypto.subtle.importKey(
      'raw',
      b64ToBuffer(pythonPubKeyB64),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Ephemeral keypair — private key non-extractable, used once.
    const ephemeralPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: pythonPubKey },
      ephemeralPair.privateKey,
      256
    );

    // HKDF key material — derive two independent keys with different info.
    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      sharedBits,
      'HKDF',
      false,
      ['deriveBits']
    );

    const enc = new TextEncoder();

    const challengeKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: enc.encode('challenge')
      },
      hkdfKey,
      256
    );

    const encKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: enc.encode('encryption')
      },
      hkdfKey,
      256
    );

    this._challengeKey = await crypto.subtle.importKey(
      'raw',
      challengeKeyBits,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    this._encKey = await crypto.subtle.importKey(
      'raw',
      encKeyBits,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );

    this._nonce = crypto.getRandomValues(new Uint8Array(32));

    const ephemeralPubBytes = await crypto.subtle.exportKey(
      'raw',
      ephemeralPair.publicKey
    );

    this.send({
      type: 'challenge',
      ephemeral_pub: bufferToB64(ephemeralPubBytes),
      nonce: bufferToB64(this._nonce)
    });
  }

  private async _verifyChallengeResponse(signatureB64: string): Promise<void> {
    if (!this._challengeKey || !this._nonce) {
      return;
    }
    const valid = await crypto.subtle.verify(
      'HMAC',
      this._challengeKey,
      b64ToBuffer(signatureB64),
      this._nonce
    );

    if (!valid) {
      console.error('SecretsWidget: challenge-response verification failed');
      return;
    }

    this._authenticated = true;
    // Challenge material no longer needed.
    this._challengeKey = null;
    this._nonce = null;

    if (this._pendingValue !== null) {
      await this._encryptAndSend(this._pendingValue);
      this._pendingValue = null;
    }
  }

  // ── Encryption ────────────────────────────────────────────────────────────

  private async _encryptAndSend(value: string): Promise<void> {
    if (!this._encKey) {
      return;
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this._encKey,
      new TextEncoder().encode(value)
    );
    this.send({
      type: 'value',
      iv: bufferToB64(iv),
      ciphertext: bufferToB64(ciphertext)
    });
  }

  private async _decrypt(
    ivB64: string,
    ciphertextB64: string
  ): Promise<string> {
    if (!this._encKey) {
      throw new Error('SecretsWidget: not authenticated');
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuffer(ivB64) },
      this._encKey,
      b64ToBuffer(ciphertextB64)
    );
    return new TextDecoder().decode(plaintext);
  }

  private _input: HTMLInputElement | null = null;
  private _onVisibilityChanged:
    | ((sender: ISecretsManager, visible: boolean) => void)
    | null = null;

  private _authenticated = false;
  private _pendingValue: string | null = null;
  private _challengeKey: CryptoKey | null = null;
  private _encKey: CryptoKey | null = null;
  private _nonce: Uint8Array | null = null;
}
