/// Proof stream with Fiat-Shamir transform.
/// Ported from the stark-anatomy Python reference implementation.
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use super::field::FieldElement;

const MAX_STREAM_OBJECTS: usize = 1_000_000;
const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_CODEWORD_ELEMENTS: usize = 1_000_000;
const MAX_PATH_SEGMENTS: usize = 1_000_000;
const MAX_PATH_SEGMENT_BYTES: usize = 1024 * 1024;

/// Objects that can be pushed/pulled from the proof stream.
#[derive(Clone, Debug)]
pub enum ProofObject {
    /// Raw bytes (Merkle root, etc.)
    Bytes(Vec<u8>),
    /// A codeword (list of field elements)
    Codeword(Vec<FieldElement>),
    /// A triple of field elements (FRI query leaf)
    Triple(FieldElement, FieldElement, FieldElement),
    /// A Merkle authentication path
    Path(Vec<Vec<u8>>),
    /// A single field element
    Element(FieldElement),
}

impl ProofObject {
    /// Serialize a single proof object to bytes (deterministic).
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ProofObject::Bytes(data) => {
                out.push(0);
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(data);
            }
            ProofObject::Codeword(elements) => {
                out.push(1);
                out.extend_from_slice(&(elements.len() as u32).to_le_bytes());
                for e in elements {
                    out.extend_from_slice(&e.value().to_le_bytes());
                }
            }
            ProofObject::Triple(a, b, c) => {
                out.push(2);
                out.extend_from_slice(&a.value().to_le_bytes());
                out.extend_from_slice(&b.value().to_le_bytes());
                out.extend_from_slice(&c.value().to_le_bytes());
            }
            ProofObject::Path(path) => {
                out.push(3);
                out.extend_from_slice(&(path.len() as u32).to_le_bytes());
                for segment in path {
                    out.extend_from_slice(&(segment.len() as u32).to_le_bytes());
                    out.extend_from_slice(segment);
                }
            }
            ProofObject::Element(e) => {
                out.push(4);
                out.extend_from_slice(&e.value().to_le_bytes());
            }
        }
        out
    }

    /// Deserialize a single proof object from bytes. Returns (object, bytes_consumed).
    fn deserialize(data: &[u8]) -> Option<(Self, usize)> {
        let tag = *data.first()?;
        let mut offset = 1;
        match tag {
            0 => {
                let len = read_u32(data, &mut offset)? as usize;
                let end = offset.checked_add(len)?;
                let bytes = data.get(offset..end)?.to_vec();
                offset = end;
                Some((ProofObject::Bytes(bytes), offset))
            }
            1 => {
                let count = read_u32(data, &mut offset)? as usize;
                let max_count_from_len = data.len().saturating_sub(offset) / 16;
                if count > MAX_CODEWORD_ELEMENTS || count > max_count_from_len {
                    return None;
                }
                let mut elements = Vec::new();
                for _ in 0..count {
                    elements.push(FieldElement::new(read_u128(data, &mut offset)?));
                }
                Some((ProofObject::Codeword(elements), offset))
            }
            2 => {
                let a = FieldElement::new(read_u128(data, &mut offset)?);
                let b = FieldElement::new(read_u128(data, &mut offset)?);
                let c = FieldElement::new(read_u128(data, &mut offset)?);
                Some((ProofObject::Triple(a, b, c), offset))
            }
            3 => {
                let count = read_u32(data, &mut offset)? as usize;
                let max_count_from_len = data.len().saturating_sub(offset) / 4;
                if count > MAX_PATH_SEGMENTS || count > max_count_from_len {
                    return None;
                }
                let mut path = Vec::new();
                for _ in 0..count {
                    let len = read_u32(data, &mut offset)? as usize;
                    if len > MAX_PATH_SEGMENT_BYTES {
                        return None;
                    }
                    let end = offset.checked_add(len)?;
                    let segment = data.get(offset..end)?.to_vec();
                    offset = end;
                    path.push(segment);
                }
                Some((ProofObject::Path(path), offset))
            }
            4 => {
                let val = read_u128(data, &mut offset)?;
                Some((ProofObject::Element(FieldElement::new(val)), offset))
            }
            _ => None,
        }
    }
}

fn read_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(u32::from_le_bytes(bytes))
}

fn read_u128(data: &[u8], offset: &mut usize) -> Option<u128> {
    let end = offset.checked_add(16)?;
    let bytes: [u8; 16] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(u128::from_le_bytes(bytes))
}

#[derive(Clone, Debug)]
pub struct ProofStream {
    pub objects: Vec<ProofObject>,
    pub read_index: usize,
}

impl Default for ProofStream {
    fn default() -> Self {
        Self::new()
    }
}

fn shake256(data: &[u8], num_bytes: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; num_bytes];
    reader.read(&mut output);
    output
}

fn serialize_objects(objects: &[ProofObject]) -> Vec<u8> {
    let mut out = Vec::new();
    for obj in objects {
        out.extend_from_slice(&obj.serialize());
    }
    out
}

impl ProofStream {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            read_index: 0,
        }
    }

    pub fn push(&mut self, obj: ProofObject) {
        self.objects.push(obj);
    }

    pub fn pull(&mut self) -> Option<ProofObject> {
        if self.read_index >= self.objects.len() {
            return None;
        }
        let obj = self.objects[self.read_index].clone();
        self.read_index += 1;
        Some(obj)
    }

    /// Serialize the entire proof stream to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.objects.len() as u32).to_le_bytes());
        for obj in &self.objects {
            let serialized = obj.serialize();
            out.extend_from_slice(&(serialized.len() as u32).to_le_bytes());
            out.extend_from_slice(&serialized);
        }
        out
    }

    /// Prover Fiat-Shamir: hash ALL objects.
    pub fn prover_fiat_shamir(&self) -> Vec<u8> {
        let data = serialize_objects(&self.objects);
        shake256(&data, 32)
    }

    /// Verifier Fiat-Shamir: hash objects up to read_index.
    pub fn verifier_fiat_shamir(&self) -> Vec<u8> {
        let data = serialize_objects(&self.objects[..self.read_index]);
        shake256(&data, 32)
    }

    /// Deserialize a proof stream from bytes.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        let mut offset = 0;
        let count = read_u32(data, &mut offset)? as usize;
        let max_count_from_len = data.len().saturating_sub(offset) / 5;
        if count > MAX_STREAM_OBJECTS || count > max_count_from_len {
            return None;
        }
        let mut objects = Vec::new();
        for _ in 0..count {
            let obj_len = read_u32(data, &mut offset)? as usize;
            if obj_len == 0 || obj_len > MAX_OBJECT_BYTES {
                return None;
            }
            let end = offset.checked_add(obj_len)?;
            let object_bytes = data.get(offset..end)?;
            let (obj, consumed) = ProofObject::deserialize(object_bytes)?;
            if consumed != object_bytes.len() {
                return None;
            }
            offset = end;
            objects.push(obj);
        }
        if offset != data.len() {
            return None;
        }
        Some(Self {
            objects,
            read_index: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_stream_push_pull() {
        let mut ps = ProofStream::new();
        ps.push(ProofObject::Bytes(vec![1, 2, 3]));
        ps.push(ProofObject::Element(FieldElement::new(42)));

        if let Some(ProofObject::Bytes(data)) = ps.pull() {
            assert_eq!(data, vec![1, 2, 3]);
        } else {
            panic!("expected Bytes");
        }
        if let Some(ProofObject::Element(e)) = ps.pull() {
            assert_eq!(e, FieldElement::new(42));
        } else {
            panic!("expected Element");
        }
    }

    #[test]
    fn test_proof_stream_serialize_deserialize() {
        let mut ps = ProofStream::new();
        ps.push(ProofObject::Bytes(vec![1, 2, 3]));
        ps.push(ProofObject::Element(FieldElement::new(42)));
        ps.push(ProofObject::Triple(
            FieldElement::new(1),
            FieldElement::new(2),
            FieldElement::new(3),
        ));

        let serialized = ps.serialize();
        let ps2 = ProofStream::deserialize(&serialized).expect("deserialize");
        assert_eq!(ps2.objects.len(), 3);
    }

    #[test]
    fn test_deserialize_rejects_truncated_stream() {
        assert!(ProofStream::deserialize(&[0, 1, 2]).is_none());
    }

    #[test]
    fn test_deserialize_rejects_huge_object_count() {
        let mut data = Vec::new();
        data.extend_from_slice(&(u32::MAX).to_le_bytes());
        assert!(ProofStream::deserialize(&data).is_none());
    }

    #[test]
    fn test_deserialize_rejects_huge_segment_length() {
        // stream count = 1
        // object length = 1 (tag) + 4 (count) + 4 (segment len)
        // object: Path with 1 segment declaring huge length
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&9u32.to_le_bytes());
        data.push(3u8);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&(MAX_PATH_SEGMENT_BYTES as u32 + 1).to_le_bytes());
        assert!(ProofStream::deserialize(&data).is_none());
    }

    #[test]
    fn test_fiat_shamir_consistency() {
        let mut ps = ProofStream::new();
        ps.push(ProofObject::Bytes(vec![1, 2, 3]));

        let prover_hash = ps.prover_fiat_shamir();

        // Simulate verifier: pull the object, then verifier_fiat_shamir should match
        let mut ps2 = ps.clone();
        let _ = ps2.pull();
        let verifier_hash = ps2.verifier_fiat_shamir();

        assert_eq!(prover_hash, verifier_hash);
    }
}
