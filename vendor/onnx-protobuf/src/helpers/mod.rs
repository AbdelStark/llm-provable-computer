use std::borrow::Cow;

use protobuf::Enum;

use crate::tensor_proto::DataType;
use crate::{attribute_proto::AttributeType, AttributeProto, GraphProto, SparseTensorProto, TensorProto, TypeProto};

/// Typed onnx attribute value
#[derive(Debug, PartialEq)]
pub enum AttributeValue<'a> {
    Unknown(i32),
    Float32(f32),
    Float32s(&'a [f32]),
    Integer64(i64),
    Integer64s(&'a [i64]),
    String(&'a [u8]),
    Strings(&'a [Vec<u8>]),
    Type(&'a TypeProto),
    Types(&'a [TypeProto]),
    Graph(&'a GraphProto),
    Graphs(&'a [GraphProto]),
    Tensor(&'a TensorProto),
    Tensors(&'a [TensorProto]),
    SparseTensor(&'a SparseTensorProto),
    SparseTensors(&'a [SparseTensorProto]),
}

impl AttributeProto {
    /// Convert to typed value
    pub fn as_value(&self) -> AttributeValue<'_> {
        match self.type_.enum_value() {
            Ok(o) => match o {
                AttributeType::UNDEFINED => AttributeValue::Unknown(0),
                AttributeType::FLOAT => AttributeValue::Float32(self.f),
                AttributeType::FLOATS => AttributeValue::Float32s(&self.floats),
                AttributeType::INT => AttributeValue::Integer64(self.i),
                AttributeType::INTS => AttributeValue::Integer64s(&self.ints),
                AttributeType::STRING => AttributeValue::String(&self.s),
                AttributeType::STRINGS => AttributeValue::Strings(&self.strings),
                AttributeType::TENSOR => match &self.t.0 {
                    Some(s) => AttributeValue::Tensor(s),
                    None => AttributeValue::Unknown(self.type_.value()),
                },
                AttributeType::TENSORS => AttributeValue::Tensors(&self.tensors),
                AttributeType::GRAPH => match &self.g.0 {
                    Some(s) => AttributeValue::Graph(s),
                    None => AttributeValue::Unknown(self.type_.value()),
                },
                AttributeType::GRAPHS => AttributeValue::Graphs(&self.graphs),
                AttributeType::SPARSE_TENSOR => match &self.sparse_tensor.0 {
                    Some(s) => AttributeValue::SparseTensor(s),
                    None => AttributeValue::Unknown(self.type_.value()),
                },
                AttributeType::SPARSE_TENSORS => AttributeValue::SparseTensors(&self.sparse_tensors),
                AttributeType::TYPE_PROTO => match &self.tp.0 {
                    Some(s) => AttributeValue::Type(s),
                    None => AttributeValue::Unknown(self.type_.value()),
                },
                AttributeType::TYPE_PROTOS => AttributeValue::Types(&self.type_protos),
            },
            Err(e) => AttributeValue::Unknown(e),
        }
    }
}

/// Typed onnx tensor value
#[derive(Debug, PartialEq)]
pub enum TensorValue<'p> {
    Unknown(i32),
    Float32(Cow<'p, [f32]>),
    Float64(Cow<'p, [f64]>),
    Unsigned32(Cow<'p, [u32]>),
    Unsigned64(Cow<'p, [u64]>),
    Integer8(Cow<'p, [i8]>),
    Integer16(Cow<'p, [i16]>),
    Integer32(Cow<'p, [i32]>),
    Integer64(Cow<'p, [i64]>),
}

fn try_convert_slice<Src, Dst>(values: &[Src]) -> Option<Vec<Dst>>
where
    Src: Copy,
    Dst: TryFrom<Src>,
{
    values
        .iter()
        .copied()
        .map(|value| Dst::try_from(value).ok())
        .collect()
}

impl TensorProto {
    /// Convert to typed value
    pub fn as_value(&self) -> TensorValue<'_> {
        match DataType::from_i32(self.data_type) {
            Some(o) => match o {
                DataType::UNDEFINED => TensorValue::Unknown(0),
                DataType::FLOAT => TensorValue::Float32(Cow::Borrowed(&self.float_data)),
                DataType::DOUBLE => TensorValue::Float64(Cow::Borrowed(&self.double_data)),
                DataType::UINT32 => try_convert_slice::<u64, u32>(&self.uint64_data)
                    .map(|values| TensorValue::Unsigned32(Cow::Owned(values)))
                    .unwrap_or(TensorValue::Unknown(self.data_type)),
                DataType::UINT64 => TensorValue::Unsigned64(Cow::Borrowed(&self.uint64_data)),
                DataType::INT8 => try_convert_slice::<i32, i8>(&self.int32_data)
                    .map(|values| TensorValue::Integer8(Cow::Owned(values)))
                    .unwrap_or(TensorValue::Unknown(self.data_type)),
                DataType::INT16 => try_convert_slice::<i32, i16>(&self.int32_data)
                    .map(|values| TensorValue::Integer16(Cow::Owned(values)))
                    .unwrap_or(TensorValue::Unknown(self.data_type)),
                DataType::INT32 => TensorValue::Integer32(Cow::Borrowed(&self.int32_data)),
                DataType::INT64 => TensorValue::Integer64(Cow::Borrowed(&self.int64_data)),
                _ => TensorValue::Unknown(self.data_type),
            },
            None => TensorValue::Unknown(self.data_type),
        }
    }
}

#[cfg(test)]
mod tests {
    use protobuf::EnumOrUnknown;

    use super::*;

    fn tensor_with_i32(data_type: DataType, int32_data: Vec<i32>) -> TensorProto {
        TensorProto {
            data_type: data_type.value(),
            int32_data,
            ..Default::default()
        }
    }

    fn tensor_with_u64(data_type: DataType, uint64_data: Vec<u64>) -> TensorProto {
        TensorProto {
            data_type: data_type.value(),
            uint64_data,
            ..Default::default()
        }
    }

    #[test]
    fn attribute_proto_as_value_returns_unknown_when_typed_payload_is_missing() {
        let attribute = AttributeProto {
            type_: EnumOrUnknown::new(AttributeType::TENSOR),
            ..Default::default()
        };

        assert_eq!(attribute.as_value(), AttributeValue::Unknown(AttributeType::TENSOR.value()));
    }

    #[test]
    fn tensor_proto_as_value_preserves_logical_element_boundaries() {
        let int8_tensor = tensor_with_i32(DataType::INT8, vec![-2, 0, 127]);
        let int16_tensor = tensor_with_i32(DataType::INT16, vec![-32_768, 17, 32_767]);
        let uint32_tensor = tensor_with_u64(DataType::UINT32, vec![1, u32::MAX as u64]);

        assert_eq!(
            int8_tensor.as_value(),
            TensorValue::Integer8(Cow::Owned(vec![-2, 0, 127]))
        );
        assert_eq!(
            int16_tensor.as_value(),
            TensorValue::Integer16(Cow::Owned(vec![-32_768, 17, 32_767]))
        );
        assert_eq!(
            uint32_tensor.as_value(),
            TensorValue::Unsigned32(Cow::Owned(vec![1, u32::MAX]))
        );
    }

    #[test]
    fn tensor_proto_as_value_rejects_out_of_range_compactions() {
        let int8_tensor = tensor_with_i32(DataType::INT8, vec![128]);
        let int16_tensor = tensor_with_i32(DataType::INT16, vec![i16::MAX as i32 + 1]);
        let uint32_tensor = tensor_with_u64(DataType::UINT32, vec![u32::MAX as u64 + 1]);

        assert_eq!(int8_tensor.as_value(), TensorValue::Unknown(DataType::INT8.value()));
        assert_eq!(
            int16_tensor.as_value(),
            TensorValue::Unknown(DataType::INT16.value())
        );
        assert_eq!(
            uint32_tensor.as_value(),
            TensorValue::Unknown(DataType::UINT32.value())
        );
    }

    #[test]
    fn tensor_proto_as_value_returns_unknown_for_unsupported_tensor_types() {
        let tensor = TensorProto {
            data_type: DataType::FLOAT16.value(),
            int32_data: vec![1],
            ..Default::default()
        };

        assert_eq!(
            tensor.as_value(),
            TensorValue::Unknown(DataType::FLOAT16.value())
        );
    }
}
