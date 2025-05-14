package org.springframework.security.saml2.provider.service.registration;

import java.util.function.Function;

import org.springframework.util.Assert;

public class LinkingRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {
	private final RelyingPartyMetadataRepository rp;
	private final AssertingPartyMetadataRepository ap;
	private Function<String, RelyingPartyRegistrationLink> registrationIdLinkFunction = (id) -> new RelyingPartyRegistrationLink(id, id, id);
	private Function<String, RelyingPartyRegistrationLink> assertingPartyEntityIdLinkFunction = (id) -> new RelyingPartyRegistrationLink(id, id, id);

	public LinkingRelyingPartyRegistrationRepository(
			RelyingPartyMetadataRepository rp,
			AssertingPartyMetadataRepository ap) {
		Assert.notNull(rp, "rp cannot be null");
		Assert.notNull(ap, "ap cannot be null");
		this.rp = rp;
		this.ap = ap;
	}

	public void setRegistrationIdLinkFunction(Function<String, RelyingPartyRegistrationLink> links) {
		this.registrationIdLinkFunction = links;
	}

	public void setAssertingPartyEntityIdLinkFunction(Function<String, RelyingPartyRegistrationLink> byAssertingPartyEntityIds) {
		this.assertingPartyEntityIdLinkFunction = byAssertingPartyEntityIds;
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		return fromEntry(this.registrationIdLinkFunction.apply(registrationId));
	}

	@Override
	public RelyingPartyRegistration findUniqueByAssertingPartyEntityId(String entityId) {
		return fromEntry(this.assertingPartyEntityIdLinkFunction.apply(entityId));
	}

	private RelyingPartyRegistration fromEntry(RelyingPartyRegistrationLink link) {
		if (link == null) {
			return null;
		}
		RelyingPartyMetadata r = this.rp.findById(link.relyingPartyMetadataId);
		AssertingPartyMetadata a = this.ap.findById(link.assertingPartyMetadataId);
		if (r == null || a == null) {
			return null;
		}
		return new RelyingPartyRegistration(link.registrationId, r, a);
	}

	public static final class RelyingPartyRegistrationLink {
		private final String registrationId;
		private final String relyingPartyMetadataId;
		private final String assertingPartyMetadataId;

		public RelyingPartyRegistrationLink(String registrationId, String relyingPartyMetadataId, String assertingPartyMetadataId) {
			this.registrationId = registrationId;
			this.relyingPartyMetadataId = relyingPartyMetadataId;
			this.assertingPartyMetadataId = assertingPartyMetadataId;
		}
	}
}
