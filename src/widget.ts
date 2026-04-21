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
      secret_id: '',
      value: ''
    };
  }

  static model_name = 'SecretsModel';
  static model_module = MODULE_NAME;
  static model_module_version = MODULE_VERSION;
  static view_name = 'SecretsView';
  static view_module = MODULE_NAME;
  static view_module_version = MODULE_VERSION;
}

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

    // Pre-fill from model if Python already set a value.
    const existingValue = this.model.get('value') as string;
    if (existingValue) {
      input.value = existingValue;
    }

    const secretId: string = this.model.get('secret_id');
    if (_manager && _token && secretId) {
      _manager
        .attach(_token, NAMESPACE, secretId, input, value => {
          this._syncToModel(value);
        })
        .catch(console.error);
    }

    input.addEventListener('input', () => this._syncToModel(input.value));

    this.listenTo(this.model, 'change:label', () => {
      label.textContent = this.model.get('label') as string;
    });

    // Reflect Python-side value changes in the input and manager.
    this.listenTo(this.model, 'change:value', () => {
      const val = this.model.get('value') as string;
      if (this._input && this._input.value !== val) {
        this._input.value = val;
        if (_manager && _token && secretId) {
          _manager
            .set(_token, NAMESPACE, secretId, {
              namespace: NAMESPACE,
              id: secretId,
              value: val
            })
            .catch(console.error);
        }
      }
    });
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

  private _syncToModel(value: string): void {
    this.model.set('value', value);
    this.model.save_changes();
  }

  private _input: HTMLInputElement | null = null;
  private _onVisibilityChanged:
    | ((sender: ISecretsManager, visible: boolean) => void)
    | null = null;
}
