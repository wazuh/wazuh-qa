import { loginXpack } from '../step-definitions/login/login-xpack';
import { loginOdfe } from '../step-definitions/login/login-odfe';
import { loginBasic } from '../step-definitions/login/login-basic';

export const LOGIN_TYPE = {
  xpack: () => loginXpack(),
  odfe: () => loginOdfe(),
  basic: () => loginBasic()
};

export const ODFE_PASSWORD = 'admin';
export const ODFE_USERNAME = 'admin';
export const OVERVIEW_URL = '/overview/';
export const XPACK_PASSWORD = 'elastic';
export const XPACK_USERNAME = 'elastic';
