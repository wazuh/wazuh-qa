import { clickElement } from '../../../utils/driver';
import { SAMPLE_DATA } from '../../../utils/mappers/sample-data-mapper';

When('The user adds/removes sample data for', (types) => {
  types.raw().forEach((sample) => {
    clickElement(SAMPLE_DATA[sample]);
    cy.wait(8000);
  });
});
