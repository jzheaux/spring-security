package org.springframework.security.saml2.provider.service.registration;

import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.StreamSupport;

public final class MappedRelyingPartyRegistrationRepository implements IterableRelyingPartyRegistrationRepository {
	private final RelyingPartyMetadataRepository relying;
	private final AssertingPartyMetadataRepository asserting;
	private final Function<String, RelyingPartyRegistrationEntry> strategy;
	private final Supplier<Iterator<RelyingPartyRegistration>> iterator;

	private MappedRelyingPartyRegistrationRepository(RelyingPartyMetadataRepository relying, AssertingPartyMetadataRepository asserting, Map<String, RelyingPartyRegistrationEntry> entries) {
		this.relying = relying;
		this.asserting = asserting;
		this.strategy = entries::get;
		this.iterator = () -> StreamSupport.stream(entries.values().spliterator(), false).map(this::fromEntry).iterator();
	}

	private MappedRelyingPartyRegistrationRepository(RelyingPartyMetadataRepository relying, AssertingPartyMetadataRepository asserting,
			Function<String, RelyingPartyRegistrationEntry> strategy, Supplier<Iterator<RelyingPartyRegistration>> iterator) {
		this.relying = relying;
		this.asserting = asserting;
		this.strategy = strategy;
		this.iterator = iterator;
	}

	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		return this.iterator.get();
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		return fromEntry(this.strategy.apply(registrationId));
	}

	private RelyingPartyRegistration fromEntry(RelyingPartyRegistrationEntry entry) {
		if (entry == null) {
			return null;
		}
		return new RelyingPartyRegistration(entry.registrationId, this.relying.findByEntityId(entry.relyingPartyEntityId), this.asserting.findByEntityId(entry.assertingPartyEntityId));
	}

	public static MappedRelyingPartyRegistrationRepository byAssertingPartyEntityId(String relyingPartyEntityId, RelyingPartyMetadataRepository relying, AssertingPartyMetadataRepository asserting) {
		return new MappedRelyingPartyRegistrationRepository(relying, asserting, (id) ->
				new RelyingPartyRegistrationEntry(id, relyingPartyEntityId, id), () ->
				() -> StreamSupport.stream(asserting.spliterator(), false)
						.map((party) -> new RelyingPartyRegistration(party.getEntityId(), relying.findByEntityId(relyingPartyEnityId), party)));
	}

	public static final class RelyingPartyRegistrationEntry {
		private final String registrationId;
		private final String relyingPartyEntityId;
		private final String assertingPartyEntityId;

		public RelyingPartyRegistrationEntry(String registrationId, String relyingPartyEntityId, String assertingPartyEntityId) {
			this.registrationId = registrationId;
			this.relyingPartyEntityId = relyingPartyEntityId;
			this.assertingPartyEntityId = assertingPartyEntityId;
		}
	}

}
