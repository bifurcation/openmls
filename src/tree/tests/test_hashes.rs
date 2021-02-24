use std::cmp::min;

use crate::{
    extensions::{Extension, RatchetTreeExtension},
    tree::*,
    utils::u32_range,
};

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

fn generate_test(n_leaves: u32, ciphersuite: &'static Ciphersuite) {
    // The key package bundle for add_sender
    let (kpb, cb) = create_identity(b"Tree creator", ciphersuite.name());

    // The new leaf key package
    // let (my_kpb, _my_cb) = create_identity(b"Tree creator", ciphersuite.name());
    // let my_key_package = my_kpb.key_package().clone();

    // The other key packages
    let mut nodes = vec![kpb];
    let mut credentials = vec![cb];
    for leaf in 0..n_leaves - 1 {
        let (kpb_i, cb_i) = create_identity(&leaf.to_be_bytes(), ciphersuite.name());
        nodes.push(kpb_i);
        credentials.push(cb_i);
    }

    // The own index (must be even)
    let add_sender = 0u32;
    let update_sender = 0u32;
    println!("add_sender: {:?}", add_sender);
    println!("update_sender: {:?}", update_sender);

    // Initialise tree
    let mut tree = RatchetTree::init(ciphersuite);
    // crate::utils::_print_tree(&tree, "Empty Tree");

    // Add leading nodes (before "self")
    // let num_leading_nodes = (add_sender.saturating_sub(1)) as usize;
    // nodes.iter().take(num_leading_nodes).for_each(|kpb| {
    //     let _ = tree.add_node(kpb.key_package());
    // });
    // crate::utils::_print_tree(&tree, "Tree with leading nodes");
    let (own_index, _own_cred) = tree.add_own_node(&nodes[add_sender as usize]);
    crate::utils::_print_tree(&tree, "Tree with own node");

    let index = tree.own_node_index().as_u32();
    assert_eq!(
        own_index.as_u32(),
        NodeIndex::from(tree.own_node_index()).as_u32()
    );

    // Add the remaining nodes to the tree.
    // let key_packages: Vec<&KeyPackage> =
    println!("index: {:?}", index);
    nodes.iter().skip(1).for_each(|kpb| {
        let _ = tree.add_node(kpb.key_package());
    });
    assert_eq!(tree.leaf_count().as_u32(), n_leaves);

    // Get and hash the tree before any operation.
    // tree.all_parent_hashes();
    assert!(tree.verify_parent_hashes().is_ok());
    // let ratchet_tree_before = tree.public_key_tree_copy();
    // let ratchet_tree_extension =
    //     RatchetTreeExtension::new(ratchet_tree_before).to_extension_struct();
    // let ratchet_tree_before_bytes = ratchet_tree_extension.extension_data();
    // let tree_hash_before = tree.tree_hash();

    // Add the new leaf for my_key_package and get the path secret for it.
    // let my_info = tree.add_nodes(&[&my_key_package]);
    // crate::utils::_print_tree(&tree, "Tree with added node");
    // let (my_node_index, _my_credential) = my_info.get(0).unwrap();
    // let mut new_indices = HashSet::new();
    // new_indices.insert(my_node_index);
    // let (_path, _key_package_bundle) = tree.refresh_private_tree(&cb, &[], new_indices);
    // let my_path_secret = tree.path_secret(*my_node_index).unwrap();
    // let my_path_secret_bytes = my_path_secret.encode_detached().unwrap();
    // let root_secret_after_add = tree.root_secret().unwrap();
    // let root_secret_after_add_bytes = root_secret_after_add.encode_detached().unwrap();

    // `update_sender` updates the tree. We don't pick the `update_sender`
    // as index in the tree but something a little more convenient.
    // Because the tree implementation is so bad we have to create a new tree
    // here for `update_sender`.
    crate::utils::_print_tree(&tree, "Tree before copy");
    let old_tree: Vec<Option<Node>> = tree.nodes.iter().map(|n| Some(n.clone())).collect();
    // let sender_index = min(update_sender as usize, credentials.len() - 1);
    // println!("Sender index: {:?}", update_sender);
    let update_sender_cb = &credentials[update_sender as usize];
    let update_sender_kpb = nodes.remove(update_sender as usize);
    let mut update_sender_tree =
        RatchetTree::new_from_nodes(ciphersuite, update_sender_kpb, &old_tree).unwrap();
    assert_eq!(tree.nodes, update_sender_tree.nodes);
    crate::utils::_print_tree(&update_sender_tree, "Update sender tree");
    // update_sender_tree.all_parent_hashes();
    let (path, _key_package_bundle) =
        update_sender_tree.refresh_private_tree(update_sender_cb, &[], HashSet::new());
    crate::utils::_print_tree(&update_sender_tree, "Tree after refresh");
    // let update_path = path.encode_detached().unwrap();
    // let root_secret_after_update = update_sender_tree.root_secret().unwrap();
    // let root_secret_after_update_bytes = root_secret_after_update.encode_detached().unwrap();
    assert!(update_sender_tree.verify_parent_hashes().is_ok());
}

// #[test]
// fn parent_hash_bug() {
//     // for _ in 0..10 {
//     // for ciphersuite in Config::supported_ciphersuites() {
//     let ciphersuite = &Config::supported_ciphersuites()[0];

//     let mut tree = RatchetTree::init(ciphersuite);

//     let (kpb_0, cb_0) = create_identity(b"First", ciphersuite.name());
//     let _ = tree.add_own_node(&kpb_0);
//     crate::utils::_print_tree(&tree, "Tree with own node");
//     let (kpb, _cb) = create_identity(b"Second", ciphersuite.name());
//     let _ = tree.add_node(kpb.key_package());
//     // let (kpb, _cb) = create_identity(b"Third", ciphersuite.name());
//     // let _ = tree.add_node(kpb.key_package());

//     // tree.all_parent_hashes(); // not necessary
//     crate::utils::_print_tree(&tree, "Tree before copy");
//     assert!(tree.verify_parent_hashes().is_ok());

//     let old_tree: Vec<Option<Node>> = tree.nodes.iter().map(|n| Some(n.clone())).collect();
//     let update_sender_cb = &cb_0;
//     let update_sender_kpb = kpb_0;
//     let mut update_sender_tree =
//         RatchetTree::new_from_nodes(ciphersuite, update_sender_kpb, &old_tree).unwrap();
//     assert_eq!(tree.nodes, update_sender_tree.nodes);
//     // update_sender_tree.all_parent_hashes();
//     crate::utils::_print_tree(&update_sender_tree, "Update sender tree");
//     let (path, _key_package_bundle) =
//         update_sender_tree.refresh_private_tree(update_sender_cb, &[], HashSet::new());
//     crate::utils::_print_tree(&update_sender_tree, "Tree after refresh");
//     println!(
//         " >>> Parent hash 0: {:x?}",
//         update_sender_tree.nodes[0].parent_hash()
//     );
//     assert!(update_sender_tree.verify_parent_hashes().is_ok());

//     println!(" ------------------------- ");

//     generate_test(2, ciphersuite);
//     // let mut new_tree =
//     //     RatchetTree::init_from_nodes(ciphersuite, &tree.public_key_tree_copy());
//     // new_tree.all_parent_hashes();
//     // crate::utils::_print_tree(&new_tree, "New tree");
//     // let (_path, _key_package_bundle) =
//     //     new_tree.refresh_private_tree(&cb, &[], HashSet::new());
//     // crate::utils::_print_tree(&new_tree, "New tree");
//     // assert!(new_tree.verify_parent_hashes().is_ok());
//     // }
//     // }
// }

#[test]
fn parent_hash_bug() {
    let ciphersuite = &Config::supported_ciphersuites()[0];

    let mut tree = RatchetTree::init(ciphersuite);

    let (kpb_0, cb_0) = create_identity(b"First", ciphersuite.name());
    let _ = tree.add_node(kpb_0.key_package());
    let (kpb_1, cb_1) = create_identity(b"Second", ciphersuite.name());
    let _ = tree.add_own_node(&kpb_1);
    crate::utils::_print_tree(&tree, "Tree with own node");
    assert!(tree.verify_parent_hashes().is_ok());
    
    let (path, _key_package_bundle) =
    tree.refresh_private_tree(&cb_1, &[], HashSet::new());
    crate::utils::_print_tree(&tree, "Tree after refresh");
    println!(
        " >>> Parent hash 2: {:x?}",
        tree.nodes[2].parent_hash()
    );
    assert!(tree.verify_parent_hashes().is_ok());
}
