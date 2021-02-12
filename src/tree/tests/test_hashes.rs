use crate::tree::*;

#[test]
fn test_parent_hash() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Number of leaf nodes in the tree
        const NODES: usize = 31;

        // Build a list of nodes, for which we need credentials and key package bundles
        let mut nodes = vec![];
        let mut key_package_bundles = vec![];
        for i in 0..NODES {
            let credential_bundle = CredentialBundle::new(
                vec![i as u8],
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
            )
            .unwrap();
            let key_package_bundle =
                KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, vec![]).unwrap();

            // We build a leaf node from the key packages
            let leaf_node = Node {
                node_type: NodeType::Leaf,
                key_package: Some(key_package_bundle.key_package().clone()),
                node: None,
            };
            key_package_bundles.push(key_package_bundle);
            nodes.push(Some(leaf_node));
            // We skip the last parent node (trees should always end with a leaf node)
            if i != NODES - 1 {
                // We insert blank parent nodes to get a longer resolution list
                nodes.push(None);
            }
        }

        // The first key package bundle is used for the tree holder
        let key_package_bundle = key_package_bundles.remove(0);

        let mut tree =
            RatchetTree::new_from_nodes(&ciphersuite, key_package_bundle, &nodes).unwrap();

        assert!(tree.verify_parent_hashes().is_ok());

        // Populate the parent nodes with fake values
        for index in 0..tree.tree_size().as_usize() {
            // Filter out leaf nodes
            if NodeIndex::from(index).is_parent() {
                let (_private_key, public_key) = ciphersuite
                    .derive_hpke_keypair(&Secret::random(ciphersuite.hash_length()))
                    .into_keys();
                let parent_node = ParentNode::new(public_key, &[], &[]);
                let node = Node {
                    key_package: None,
                    node: Some(parent_node),
                    node_type: NodeType::Parent,
                };
                tree.nodes[index] = node;
            }
        }

        // Compute the recursive parent_hash for the first member
        let original_parent_hash = tree.set_parent_hashes(LeafIndex::from(0usize));

        // Swap two leaf nodes in the left & right part of the tree
        tree.nodes.swap(15, 47);

        // Compute the parent hash again to verify it has changed
        let leaf_swap_parent_hash = tree.set_parent_hashes(LeafIndex::from(0usize));

        assert!(leaf_swap_parent_hash != original_parent_hash);
    }
}

fn create_identity(
    id: &[u8],
    ciphersuite_name: CiphersuiteName,
) -> (KeyPackageBundle, CredentialBundle) {
    let signature_scheme = SignatureScheme::from(ciphersuite_name);
    let credential_bundle =
        CredentialBundle::new(id.to_vec(), CredentialType::Basic, signature_scheme).unwrap();
    (
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap(),
        credential_bundle,
    )
}

#[test]
fn parent_hash_bug() {
    let ciphersuite = &Config::supported_ciphersuites()[0];

    let mut tree = RatchetTree::init(ciphersuite);

    let (kpb, _cb) = create_identity(b"First", ciphersuite.name());
    let _ = tree.add_node(kpb.key_package());
    let (kpb, _cb) = create_identity(b"Second", ciphersuite.name());
    let _ = tree.add_node(kpb.key_package());
    let (kpb, cb) = create_identity(b"Third", ciphersuite.name());
    let _ = tree.add_node(kpb.key_package());

    tree.all_parent_hashes(); // not necessary
    assert!(tree.verify_parent_hashes().is_ok());

    let mut new_tree = RatchetTree::init_from_nodes(ciphersuite, &tree.public_key_tree_copy());
    new_tree.all_parent_hashes();
    let (_path, _key_package_bundle) = new_tree.refresh_private_tree(&cb, &[], HashSet::new());
    assert!(new_tree.verify_parent_hashes().is_ok());
}
