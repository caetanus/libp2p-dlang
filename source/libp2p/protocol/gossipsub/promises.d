/**
 * IWANT promises: when we ask a peer for a message it offered, we expect it
 * within the follow-up window. A promise that lapses is a broken one and
 * counts against the peer (P7); delivery or rejection cancels it, except a
 * rejection for claiming our own origin, which the peer still answers for.
 */
module libp2p.protocol.gossipsub.promises;

import core.time : MonoTime;

import libp2p.core.peer_id : PeerId;
import libp2p.protocol.gossipsub.score : RejectReason;

struct GossipPromises
{
	private MonoTime[PeerId][string] promises; // id → peer → deadline

	/// Track `ids` as promised by `peer` until `expires`. The earliest promise
	/// per (peer, id) stands; a later one does not extend it.
	void addPromise(PeerId peer, string[] ids, MonoTime expires)
	{
		foreach (id; ids)
		{
			auto byPeer = promises.get(id, null);
			if (peer !in byPeer)
				byPeer[peer] = expires;
			promises[id] = byPeer;
		}
	}

	bool contains(string id) const @safe pure nothrow
	{
		return (id in promises) !is null;
	}

	void messageDelivered(string id)
	{
		promises.remove(id);
	}

	void rejectMessage(string id, RejectReason reason)
	{
		if (reason == RejectReason.selfOrigin)
			return; // the peer still owes an answer for this one
		promises.remove(id);
	}

	/// Promises past their deadline, counted per peer and removed.
	size_t[PeerId] getBrokenPromises(MonoTime now)
	{
		size_t[PeerId] broken;
		string[] emptied;
		foreach (id, ref byPeer; promises)
		{
			PeerId[] late;
			foreach (peer, deadline; byPeer)
				if (now > deadline)
				{
					broken[peer] = broken.get(peer, 0) + 1;
					late ~= peer;
				}
			foreach (p; late)
				byPeer.remove(p);
			if (byPeer.length == 0)
				emptied ~= id;
		}
		foreach (id; emptied)
			promises.remove(id);
		return broken;
	}
}
