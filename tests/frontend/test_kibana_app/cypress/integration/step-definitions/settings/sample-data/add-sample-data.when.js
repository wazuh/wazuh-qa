import { clickElement } from '../../../utils/driver';
import { SAMPLE_DATA } from '../../../utils/sample-data-constants';

When('The user adds/removes sample {} data', (type) => {
  clickElement(SAMPLE_DATA[type]);
});
