pragma solidity ^0.6.0;

import "./Ownable.sol";
import "./Item.sol";

contract ItemManager is Ownable {
    
    //…
    
    function createItem(string memory _identifier, uint _priceInWei) public onlyOwner {
    //…
    }
    
    function triggerPayment(uint _index) public payable {
    //…
    }
    
    function triggerDelivery(uint _index) public onlyOwner {
    //…
    }
