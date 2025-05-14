package org.springframework.security.saml2.provider.service.registration;

import java.util.function.Function;

import org.springframework.util.Assert;

/**
 * This class allows relying parties and asserting parties to be retreived separately and
 * then linked together dynamically.
 *
 * By default, {@link #findByRegistrationId} will query the provided
 * {@link RelyingPartyMetadataRepository} and {@link AssertingPartyMetadataRepository}
 * using the provided {@code registrationId}.
 *
 * To provide an alternative mapping strategy, you can provide a function that indicates
 * the appropriate ids to use to query the two repositories. For example, if the
 * association between registration id and relying and asserting parties is in a join
 * table, this allows you to do:
 *
 * <code>
 *     Function&lt;String, RelyingPartyRegistrationLink&gt; link = myJoinTableRepository::findByRegistrationId;
 * </code>
 *
 * Since {@code entityId} is not a virtual identifier like
 * {@code registrationId} is, {@link #findUniqueByAssertingPartyEntityId} always queries
 * the repositories by the {@code entityId}.
 *
 * By default, this will set the {@code registrationId} to the asserting party's {@link AssertingPartyMetadata#getId()}.
 *
 * To provide an alternative mapping strategy, you can provide a function and indicates
 * the appropriate registration id to derive from the two metadata identifiers:
 *
 * <code>
 *     Function&lt;RelyingPartyRegistrationLink, String&gt; link = myJoinTableRepository::findRegistrationIdByLink;
 * </code>
 */
public final class LinkingRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {
	private final RelyingPartyMetadataRepository rp;
	private final AssertingPartyMetadataRepository ap;
	private Function<String, RelyingPartyRegistrationLink> registrationIdLinkFunction = (id) -> new RelyingPartyRegistrationLink(id, id);
	private Function<RelyingPartyRegistrationLink, String> linkRegistrationIdFunction = (link) -> link.assertingPartyMetadataId;

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

	public void setLinkRegistrationIdFunction(Function<RelyingPartyRegistrationLink, String> linkRegistrationIdFunction) {
		this.linkRegistrationIdFunction = linkRegistrationIdFunction;
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		RelyingPartyRegistrationLink link = this.registrationIdLinkFunction.apply(registrationId);
		if (link == null) {
			return null;
		}
		RelyingPartyMetadata relyingParty = this.rp.findById(link.relyingPartyMetadataId);
		AssertingPartyMetadata assertingParty = this.ap.findById(link.assertingPartyMetadataId);
		return new RelyingPartyRegistration(registrationId, relyingParty, assertingParty);
	}

	@Override
	public RelyingPartyRegistration findUniqueByAssertingPartyEntityId(String entityId) {
		RelyingPartyMetadata relyingParty = this.rp.findUniqueByAssertingPartyEntityId(entityId);
		if (relyingParty == null) {
			return null;
		}
		AssertingPartyMetadata assertingParty = this.ap.findByEntityId(entityId);
		if (assertingParty == null) {
			return null;
		}
		RelyingPartyRegistrationLink link = new RelyingPartyRegistrationLink(relyingParty.getId(), assertingParty.getId());
		return new RelyingPartyRegistration(this.linkRegistrationIdFunction.apply(link), relyingParty, assertingParty);
	}

	public static final class RelyingPartyRegistrationLink {
		private final String relyingPartyMetadataId;
		private final String assertingPartyMetadataId;

		public RelyingPartyRegistrationLink(String relyingPartyMetadataId, String assertingPartyMetadataId) {
			this.relyingPartyMetadataId = relyingPartyMetadataId;
			this.assertingPartyMetadataId = assertingPartyMetadataId;
		}
	}
}
