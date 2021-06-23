import { elementIsVisible } from '../../../utils/driver';
import {
  appRevisionNumber,
  appRevisionTitle,
  appVersionNumber,
  appVersionTitle,
  communityCard,
  communityCardTitle,
  communityGithubLink,
  communityGoogleGroupLink,
  communitySlackLink,
  installDateInformation,
  installDateTitle,
  welcomingCard,
  welcomingCardTitle,
} from '../../../pageobjects/settings/about.page';

Then('The Wazuh information is displayed', () => {
  elementIsVisible(appVersionTitle);
  elementIsVisible(appVersionNumber);

  elementIsVisible(appRevisionTitle);
  elementIsVisible(appRevisionNumber);

  elementIsVisible(installDateTitle);
  elementIsVisible(installDateInformation);

  elementIsVisible(welcomingCard);
  elementIsVisible(welcomingCardTitle);

  elementIsVisible(communityCard);
  elementIsVisible(communityCardTitle);
  elementIsVisible(communitySlackLink);
  elementIsVisible(communityGoogleGroupLink);
  elementIsVisible(communityGithubLink);
});
