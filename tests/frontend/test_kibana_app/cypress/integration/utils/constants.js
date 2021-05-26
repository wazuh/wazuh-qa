import { loginXpack } from '../step-definitions/login/login-xpack';
import { loginOdfe } from '../step-definitions/login/login-odfe';
import { loginBasic } from '../step-definitions/login/login-basic';
import { loginDefault } from '../step-definitions/login/login-default';

export const LOGIN_TYPE = {
  xpack: () => loginXpack,
  odfe: () => loginOdfe,
  basic: () => loginBasic,
  default: () => loginDefault,
};

export const ODFE_PASSWORD = 'admin';
export const ODFE_USERNAME = 'admin';
export const XPACK_PASSWORD = 'elastic';
export const XPACK_USERNAME = 'elastic';
