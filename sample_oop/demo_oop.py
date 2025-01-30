# Define a simple class representing a Dog
class Dog:
    """A simple Dog class demonstrating OOP principles."""
    
    def __init__(self, name: str, breed: str, age: int):
        """Initialize the Dog instance with name, breed, and age.
        
        Args:
            name (str): The name of the dog.
            breed (str): The breed of the dog.
            age (int): The age of the dog.
        
        "self" represents the instance of the class. It is used to access attributes and methods of the object.
        When you create an object (dog1 = Dog("Buddy", "Golden Retriever", 3)), Python automatically passes that instance (dog1) as "self" in the __init__ method.
        "self" is required in instance methods because it ensures that attributes and behaviors are tied to a specific object, not shared across all instances.

        """
        self.name = name  # Instance variable for the dog's name
        self.breed = breed  # Instance variable for the dog's breed
        self.age = age  # Instance variable for the dog's age
        #Without "self", we wouldn't be able to uniquely associate attributes with specific objects.
    
    def bark(self) -> str:
        """Make the dog bark.
        
        Returns:
            str: The bark sound with the dog's name.
        """
        return f"{self.name} says: Woof!"
    
    def get_age(self) -> int:
        """Get the age of the dog.
        
        Returns:
            int: The dog's age.
        """
        return self.age
    
    def celebrate_birthday(self):
        """Increase the dog's age by one year."""
        self.age += 1
        print(f"Happy Birthday, {self.name}! You are now {self.age} years old!")

# Inheritance - Creating a specialized class from the Dog class
class GuideDog(Dog):
    """A specialized GuideDog class that inherits from Dog."""
    
    def __init__(self, name: str, breed: str, age: int, trained: bool):
        """Initialize the GuideDog instance with an additional trained attribute.
        
        Args:
            name (str): The name of the dog.
            breed (str): The breed of the dog.
            age (int): The age of the dog.
            trained (bool): Whether the guide dog is trained.
        """
        super().__init__(name, breed, age)  # Call the parent class constructor
        self.trained = trained  # Instance variable for training status
    
    def guide(self) -> str:
        """Simulate the guide dog assisting.
        
        Returns:
            str: A message about guiding the owner.
        """
        if self.trained:
            return f"{self.name} is guiding the owner safely!"
        else:
            return f"{self.name} is not trained yet!"

# Example Usage
if __name__ == "__main__":
    # Create instances of Dog and GuideDog
    dog1 = Dog("Buddy", "Golden Retriever", 3)
    guide_dog = GuideDog("Rex", "Labrador", 5, trained=True)
    
    # Display basic information and behaviors
    print(dog1.bark())
    print(f"{dog1.name} is {dog1.get_age()} years old.")
    dog1.celebrate_birthday()
    
    # Guide dog specific behavior
    print(guide_dog.bark())
    print(guide_dog.guide())
