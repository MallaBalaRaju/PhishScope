import { 
  GraphNode, 
  GraphEdge, 
  EmailEnvelope, 
  ReceivedHop, 
  ExtractedUrl, 
  InfrastructureObservation 
} from '../../src/types/forensics';

export interface EmailGraphBuildInput {
  analysisId: string;
  envelope: EmailEnvelope;
  receivedHops: ReceivedHop[];
  candidateSourceIps: Array<{ ip: string; confidence: string }>;
  urls: ExtractedUrl[];
  observations: InfrastructureObservation[];
}

/**
 * Builds an infrastructure relationship graph for a single email.
 * Every node and edge captures entity type, relationship type, evidence source,
 * timestamp, directly observed vs inferred relationship, and confidence indicator.
 */
export function buildEmailGraph(input: EmailGraphBuildInput): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodesMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const now = new Date().toISOString();

  // 1. Email Root Node
  const emailNodeId = `email:${input.analysisId}`;
  nodesMap.set(emailNodeId, {
    id: emailNodeId,
    type: 'email',
    label: input.envelope.subject ? `Email: "${input.envelope.subject.slice(0, 30)}..."` : `Email: ${input.analysisId.slice(0, 8)}`,
    evidenceReferences: ['Message Envelope'],
    attributes: {
      analysisId: input.analysisId,
      date: input.envelope.date
    }
  });

  // 2. Sender Address & Domain
  if (input.envelope.from?.address) {
    const senderAddrId = `addr:${input.envelope.from.address.toLowerCase()}`;
    nodesMap.set(senderAddrId, {
      id: senderAddrId,
      type: 'sender_address',
      label: input.envelope.from.address,
      evidenceReferences: ['From Header']
    });

    edges.push({
      id: `edge:${emailNodeId}->${senderAddrId}`,
      sourceNode: emailNodeId,
      targetNode: senderAddrId,
      relationshipType: 'SENT_FROM',
      evidenceReferences: ['From Header'],
      confidence: 'confirmed_direct',
      isDirectlyObserved: true,
      relationshipNature: 'directly_observed',
      observedAt: now,
      supportingObservation: 'Direct RFC 5322 From header declaration.'
    });

    if (input.envelope.from.domain) {
      const senderDomainId = `domain:${input.envelope.from.domain.toLowerCase()}`;
      nodesMap.set(senderDomainId, {
        id: senderDomainId,
        type: 'sender_domain',
        label: input.envelope.from.domain,
        evidenceReferences: ['From Header Domain']
      });

      edges.push({
        id: `edge:${senderAddrId}->${senderDomainId}`,
        sourceNode: senderAddrId,
        targetNode: senderDomainId,
        relationshipType: 'ASSOCIATED_WITH',
        evidenceReferences: ['RFC 5322 Address Parsing'],
        confidence: 'confirmed_direct',
        isDirectlyObserved: true,
        relationshipNature: 'directly_observed',
        observedAt: now,
        supportingObservation: 'Domain parsed from mailbox syntax.'
      });
    }
  }

  // 3. Candidate Source IPs & Mail Relays
  for (const candidate of input.candidateSourceIps) {
    const ipNodeId = `ip:${candidate.ip}`;
    nodesMap.set(ipNodeId, {
      id: ipNodeId,
      type: 'candidate_source_ip',
      label: `IP: ${candidate.ip}`,
      evidenceReferences: ['Received Header Chain'],
      attributes: { confidence: candidate.confidence }
    });

    edges.push({
      id: `edge:${emailNodeId}->${ipNodeId}`,
      sourceNode: emailNodeId,
      targetNode: ipNodeId,
      relationshipType: 'ROUTED_THROUGH',
      evidenceReferences: ['Received Hops'],
      confidence: 'derived',
      isDirectlyObserved: false,
      relationshipNature: 'inferred',
      observedAt: now,
      supportingObservation: `Identified candidate sending IP with confidence ${candidate.confidence}. Derived from chronological hop reconstruction.`
    });
  }

  // 4. Mail Servers from Hops
  let hopIndex = 0;
  for (const hop of input.receivedHops) {
    hopIndex++;
    if (hop.byServer) {
      const serverNodeId = `server:${hop.byServer.toLowerCase()}`;
      if (!nodesMap.has(serverNodeId)) {
        nodesMap.set(serverNodeId, {
          id: serverNodeId,
          type: 'mail_server',
          label: hop.byServer,
          evidenceReferences: [`Received Hop #${hopIndex}`]
        });
      }

      edges.push({
        id: `edge:${emailNodeId}->${serverNodeId}:${hopIndex}`,
        sourceNode: emailNodeId,
        targetNode: serverNodeId,
        relationshipType: 'ROUTED_THROUGH',
        evidenceReferences: [`Received Hop #${hopIndex}`],
        confidence: hop.isBorderHop ? 'confirmed_direct' : 'derived',
        isDirectlyObserved: hop.isBorderHop,
        relationshipNature: hop.isBorderHop ? 'directly_observed' : 'inferred',
        observedAt: now,
        supportingObservation: hop.isBorderHop
          ? `Logged by trusted recipient border MTA (hop position #${hop.rawPositionFromTop}).`
          : `Processed by mail relay at chronological hop #${hopIndex}.`
      });
    }
  }

  // 5. Extracted URLs and Destination Domains
  const seenUrls = new Set<string>();
  for (const url of input.urls) {
    if (seenUrls.size >= 5) break; // Limit to 5 top URLs in primary graph to avoid visual clutter
    if (!seenUrls.has(url.url)) {
      seenUrls.add(url.url);
      const urlNodeId = `url:${url.url}`;
      nodesMap.set(urlNodeId, {
        id: urlNodeId,
        type: 'url',
        label: url.defangedUrl.length > 32 ? `${url.defangedUrl.slice(0, 32)}...` : url.defangedUrl,
        evidenceReferences: ['Message Body Link'],
        attributes: {
          isMismatch: url.isMismatch,
          isIpBased: url.isIpBased
        }
      });

      edges.push({
        id: `edge:${emailNodeId}->${urlNodeId}`,
        sourceNode: emailNodeId,
        targetNode: urlNodeId,
        relationshipType: 'OBSERVED_IN_EMAIL',
        evidenceReferences: ['Message Body'],
        confidence: 'confirmed_direct',
        isDirectlyObserved: true,
        relationshipNature: 'directly_observed',
        observedAt: now,
        supportingObservation: 'Direct observation in HTML or plain text message body.'
      });

      if (url.domain) {
        const destDomainId = `domain:${url.domain.toLowerCase()}`;
        if (!nodesMap.has(destDomainId)) {
          nodesMap.set(destDomainId, {
            id: destDomainId,
            type: 'related_domain',
            label: url.domain,
            evidenceReferences: ['Extracted URL Hostname']
          });
        }

        edges.push({
          id: `edge:${urlNodeId}->${destDomainId}`,
          sourceNode: urlNodeId,
          targetNode: destDomainId,
          relationshipType: 'RESOLVES_TO',
          evidenceReferences: ['URL Authority Component'],
          confidence: 'confirmed_direct',
          isDirectlyObserved: true,
          relationshipNature: 'directly_observed',
          observedAt: now,
          supportingObservation: 'URL authority component extracted via RFC 3986 parser.'
        });
      }
    }
  }

  // 6. External DNS Observations
  for (const obs of input.observations) {
    if (obs.status === 'available' && obs.observation.resolvedAIPv4) {
      const domainNodeId = `domain:${obs.entity.toLowerCase()}`;
      if (nodesMap.has(domainNodeId)) {
        for (const aIp of (obs.observation.resolvedAIPv4 as string[]).slice(0, 2)) {
          const aIpNodeId = `ip:${aIp}`;
          if (!nodesMap.has(aIpNodeId)) {
            nodesMap.set(aIpNodeId, {
              id: aIpNodeId,
              type: 'candidate_source_ip',
              label: `Resolved IP: ${aIp}`,
              evidenceReferences: [`DNS A Record for ${obs.entity}`]
            });
          }

          edges.push({
            id: `edge:${domainNodeId}->${aIpNodeId}`,
            sourceNode: domainNodeId,
            targetNode: aIpNodeId,
            relationshipType: 'RESOLVES_TO',
            evidenceReferences: ['Live DNS Query'],
            confidence: 'derived',
            isDirectlyObserved: false,
            relationshipNature: 'inferred',
            observedAt: now,
            supportingObservation: `Live DNS A record resolved ${obs.entity} to ${aIp}. Caveat: shared CDN or multi-tenant IP does not indicate common ownership.`
          });
        }
      }
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges
  };
}

/**
 * Builds a global session correlation graph across all analyzed emails.
 * Detects shared candidate IPs, sender domains, and URLs.
 * Emits SHARES_INFRASTRUCTURE_WITH edges with explicit caveats regarding shared hosting and multi-tenant services.
 */
export function buildSessionCorrelationGraph(analyses: Array<{
  analysisId: string;
  subject?: string;
  senderDomain?: string;
  senderAddress?: string;
  candidateIps: string[];
  urlDomains: string[];
}>): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodesMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const now = new Date().toISOString();

  const ipToEmails = new Map<string, string[]>();
  const domainToEmails = new Map<string, string[]>();

  for (const a of analyses) {
    const emailNodeId = `email:${a.analysisId}`;
    nodesMap.set(emailNodeId, {
      id: emailNodeId,
      type: 'email',
      label: a.subject ? `"${a.subject.slice(0, 24)}..."` : `Email: ${a.analysisId.slice(0, 8)}`,
      evidenceReferences: ['Session Investigation Analysis']
    });

    if (a.senderDomain) {
      const dId = `domain:${a.senderDomain.toLowerCase()}`;
      if (!nodesMap.has(dId)) {
        nodesMap.set(dId, {
          id: dId,
          type: 'sender_domain',
          label: a.senderDomain,
          evidenceReferences: ['Sender Domain']
        });
      }
      edges.push({
        id: `sess_edge:${emailNodeId}->${dId}`,
        sourceNode: emailNodeId,
        targetNode: dId,
        relationshipType: 'SENT_FROM',
        evidenceReferences: ['From Header'],
        confidence: 'confirmed_direct',
        isDirectlyObserved: true,
        relationshipNature: 'directly_observed',
        observedAt: now
      });

      const list = domainToEmails.get(a.senderDomain.toLowerCase()) || [];
      list.push(emailNodeId);
      domainToEmails.set(a.senderDomain.toLowerCase(), list);
    }

    for (const ip of a.candidateIps) {
      const ipId = `ip:${ip}`;
      if (!nodesMap.has(ipId)) {
        nodesMap.set(ipId, {
          id: ipId,
          type: 'candidate_source_ip',
          label: ip,
          evidenceReferences: ['Routing Chain']
        });
      }
      edges.push({
        id: `sess_edge:${emailNodeId}->${ipId}`,
        sourceNode: emailNodeId,
        targetNode: ipId,
        relationshipType: 'ROUTED_THROUGH',
        evidenceReferences: ['Received Hops'],
        confidence: 'derived',
        isDirectlyObserved: false,
        relationshipNature: 'inferred',
        observedAt: now
      });

      const list = ipToEmails.get(ip) || [];
      list.push(emailNodeId);
      ipToEmails.set(ip, list);
    }
  }

  // Correlate emails sharing candidate IPs (Potential infrastructure cluster)
  for (const [ip, emailList] of ipToEmails) {
    if (emailList.length > 1) {
      for (let i = 0; i < emailList.length; i++) {
        for (let j = i + 1; j < emailList.length; j++) {
          edges.push({
            id: `corr_ip:${emailList[i]}<->${emailList[j]}:${ip}`,
            sourceNode: emailList[i],
            targetNode: emailList[j],
            relationshipType: 'SHARES_INFRASTRUCTURE_WITH',
            evidenceReferences: [`Candidate IP ${ip}`],
            confidence: 'hypothesized',
            isDirectlyObserved: false,
            relationshipNature: 'correlated',
            observedAt: now,
            supportingObservation: `Both messages route through common IP ${ip}. Exploratory correlation: shared hosting providers, shared mail relays, or multi-tenant CDNs do NOT prove common ownership or unified attacker attribution.`
          });
        }
      }
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges
  };
}
