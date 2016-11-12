if [ "$#" -ne 1 ]
then
  echo "Usage: $0 No_of_switches" >&2
  exit 1
fi

for i in `seq 1 $1`
do
	sudo ovs-vsctl set bridge s$i protocols=OpenFlow13
	echo "Setting up switch $i"
done
