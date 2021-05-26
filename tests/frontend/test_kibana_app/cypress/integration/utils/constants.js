import { loginXpack } from '../step-definitions/login/login-xpack';
import { loginOdfe } from '../step-definitions/login/login-odfe';

export const ODFE_PASSWORD = 'admin';
export const ODFE_USERNAME = 'admin';
export const XPACK_PASSWORD = 'elastic';
export const XPACK_USERNAME = 'elastic';

export const LOGIN_TYPE = {
  xpack: () => loginXpack,
  odfe: () => loginOdfe,
  basic: () => console.log(`Parameter loginMethod is: BASIC`),
  default: loginMethod => console.error(`Parameter loginMethod is: ${loginMethod}`),
};
